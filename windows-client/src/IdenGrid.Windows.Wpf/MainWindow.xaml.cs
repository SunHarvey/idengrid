using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Net.Http;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using IdenGrid.Core;

namespace IdenGrid.Windows.Wpf;

public partial class MainWindow : Window
{
    private readonly HttpClient _http;
    private readonly NativeApiClient _api;
    private readonly WindowsStoreProcessManager _processes;
    private readonly WindowsSessionVault _sessionVault = new();
    private readonly ObservableCollection<StoreRow> _visibleStores = [];
    private IReadOnlyList<StoreDto> _allStores = [];
    private SessionDto? _session;
    private CancellationTokenSource? _refreshCancellation;
    private bool _isRefreshing;
    private int _refreshRetryAttempt;
    private bool _showsPassword;
    private bool _allowClose;

    public MainWindow()
    {
        InitializeComponent();
        var deviceId = DeviceIdentity.Current();
        var apiBase = ClientConfiguration.LoadApiBaseAddress();
        _http = new HttpClient
        {
            BaseAddress = apiBase,
            Timeout = TimeSpan.FromSeconds(30),
        };
        _api = new NativeApiClient(_http);
        _processes = new WindowsStoreProcessManager(apiBase, deviceId);
        _processes.StateChanged += _ => Dispatcher.Invoke(ApplyStoreFilter);
        StoreList.ItemsSource = _visibleStores;
        Loaded += async (_, _) => await RestoreSessionAsync();
        Closing += WindowClosing;
        Closed += (_, _) =>
        {
            _refreshCancellation?.Cancel();
            _refreshCancellation?.Dispose();
            _http.Dispose();
        };
    }

    private async void LoginClick(object sender, RoutedEventArgs e)
    {
        var username = UsernameBox.Text.Trim();
        var password = _showsPassword ? VisiblePasswordBox.Text : PasswordBox.Password;
        if (username.Length == 0 || password.Length == 0)
        {
            ShowLoginStatus("请输入用户名和密码", true);
            return;
        }

        LoginButton.IsEnabled = false;
        LoginButton.Content = "登录中…";
        ShowLoginStatus("正在连接", false);
        try
        {
            var session = await _api.LoginAsync(
                username,
                password,
                DeviceIdentity.Current(),
                Environment.MachineName);
            await BeginAuthenticatedSessionAsync(session, save: true);
        }
        catch (ApiException error)
        {
            ShowLoginStatus(LoginPresentation.FailureMessage(error.StatusCode), true);
        }
        catch
        {
            ShowLoginStatus(LoginPresentation.FailureMessage(null), true);
        }
        finally
        {
            PasswordBox.Clear();
            VisiblePasswordBox.Clear();
            SetPasswordVisibility(false);
            LoginButton.Content = "登录";
            LoginButton.IsEnabled = true;
        }
    }

    private void TogglePasswordVisibility(object sender, RoutedEventArgs e) =>
        SetPasswordVisibility(!_showsPassword);

    private void SetPasswordVisibility(bool show)
    {
        if (show)
        {
            VisiblePasswordBox.Text = PasswordBox.Password;
            PasswordBox.Visibility = Visibility.Collapsed;
            VisiblePasswordBox.Visibility = Visibility.Visible;
            PasswordSlash.Visibility = Visibility.Visible;
            PasswordVisibilityButton.ToolTip = "隐藏密码";
            System.Windows.Automation.AutomationProperties.SetName(
                PasswordVisibilityButton,
                "隐藏密码");
            VisiblePasswordBox.Focus();
            VisiblePasswordBox.CaretIndex = VisiblePasswordBox.Text.Length;
        }
        else
        {
            if (_showsPassword) PasswordBox.Password = VisiblePasswordBox.Text;
            VisiblePasswordBox.Clear();
            VisiblePasswordBox.Visibility = Visibility.Collapsed;
            PasswordBox.Visibility = Visibility.Visible;
            PasswordSlash.Visibility = Visibility.Collapsed;
            PasswordVisibilityButton.ToolTip = "显示密码";
            System.Windows.Automation.AutomationProperties.SetName(
                PasswordVisibilityButton,
                "显示密码");
            if (_showsPassword) PasswordBox.Focus();
        }
        _showsPassword = show;
    }

    private async void RefreshClick(object sender, RoutedEventArgs e) => await LoadStoresAsync();

    private void SearchChanged(object sender, TextChangedEventArgs e) => ApplyStoreFilter();

    private async void StorePrimaryClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { DataContext: StoreRow row } || _session is null) return;
        if (_processes.IsRunning(row.Id))
        {
            _processes.Activate(row.Id);
            return;
        }

        WorkspaceStatus.Text = $"正在启动 {row.Name}";
        try
        {
            await _processes.LaunchAsync(row.Store, _session.AccessToken);
            WorkspaceStatus.Text = $"{row.Name} 已连接固定出口";
        }
        catch (Exception error)
        {
            WorkspaceStatus.Text = $"{row.Name} 启动失败：{SafeLaunchError(error)}";
        }
        finally
        {
            ApplyStoreFilter();
        }
    }

    private async void StoreCloseClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { DataContext: StoreRow row }) return;
        WorkspaceStatus.Text = $"正在关闭 {row.Name}";
        await _processes.CloseAsync(row.Id);
        WorkspaceStatus.Text = $"{row.Name} 已关闭";
        ApplyStoreFilter();
    }

    private async void QuitAllClick(object sender, RoutedEventArgs e)
    {
        WorkspaceStatus.Text = "正在关闭全部店铺";
        await _processes.QuitAllAsync();
        WorkspaceStatus.Text = "全部店铺已关闭";
        ApplyStoreFilter();
    }

    private async void LogoutClick(object sender, RoutedEventArgs e)
    {
        _refreshCancellation?.Cancel();
        await _processes.QuitAllAsync();
        if (_session is not null)
        {
            try { await _api.LogoutAsync(_session.AccessToken); }
            catch { }
        }
        _sessionVault.Clear();
        _session = null;
        _allStores = [];
        _visibleStores.Clear();
        SearchBox.Clear();
        StorePanel.Visibility = Visibility.Collapsed;
        LoginPanel.Visibility = Visibility.Visible;
        ShowLoginStatus("已退出登录", false);
    }

    private async Task RestoreSessionAsync()
    {
        var stored = _sessionVault.Load();
        if (stored is null) return;
        LoginButton.IsEnabled = false;
        ShowLoginStatus("正在恢复会话", false);
        try
        {
            var refreshed = await _api.RefreshAsync(stored.RefreshToken);
            await BeginAuthenticatedSessionAsync(refreshed, save: true);
            ShowLoginStatus("会话已恢复", false);
        }
        catch (ApiException error) when (error.StatusCode is 401 or 403)
        {
            _sessionVault.Clear();
            ShowLoginStatus("会话已过期，请重新登录", true);
        }
        catch
        {
            ShowLoginStatus("暂时无法恢复会话，请检查网络后重试", true);
        }
        finally
        {
            LoginButton.IsEnabled = true;
        }
    }

    private async Task BeginAuthenticatedSessionAsync(SessionDto session, bool save)
    {
        _session = session;
        if (save) _sessionVault.Save(session);
        LoginPanel.Visibility = Visibility.Collapsed;
        StorePanel.Visibility = Visibility.Visible;
        await LoadStoresAsync();
        _refreshRetryAttempt = 0;
        StartRefreshScheduler();
    }

    private void StartRefreshScheduler(TimeSpan? overrideDelay = null)
    {
        _refreshCancellation?.Cancel();
        _refreshCancellation?.Dispose();
        if (_session is null) return;
        _refreshCancellation = new CancellationTokenSource();
        var delay = overrideDelay ?? AccessTokenRefreshSchedule.Delay(
            _session.AccessExpiresAt,
            DateTimeOffset.UtcNow);
        _ = RefreshAfterDelayAsync(delay, _refreshCancellation.Token);
    }

    private async Task RefreshAfterDelayAsync(TimeSpan delay, CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(delay, cancellationToken);
            await RefreshAccessTokenAsync();
        }
        catch (OperationCanceledException) { }
    }

    private async Task RefreshAccessTokenAsync()
    {
        if (_isRefreshing || _session is null) return;
        _isRefreshing = true;
        try
        {
            var stored = _sessionVault.Load()
                ?? throw new InvalidOperationException("本地设备会话不存在");
            var refreshed = await _api.RefreshAsync(stored.RefreshToken);
            _session = refreshed;
            _sessionVault.Save(refreshed);
            await _processes.UpdateAccessTokenAsync(refreshed.AccessToken);
            _refreshRetryAttempt = 0;
            StartRefreshScheduler();
        }
        catch (ApiException error) when (error.StatusCode is 401 or 403)
        {
            await FailClosedSessionAsync("会话已过期，请重新登录");
        }
        catch
        {
            var retry = AccessTokenRefreshSchedule.RetryDelay(_refreshRetryAttempt);
            _refreshRetryAttempt += 1;
            StartRefreshScheduler(retry);
        }
        finally
        {
            _isRefreshing = false;
        }
    }

    private async Task FailClosedSessionAsync(string message)
    {
        _refreshCancellation?.Cancel();
        await _processes.QuitAllAsync();
        _sessionVault.Clear();
        _session = null;
        _allStores = [];
        _visibleStores.Clear();
        StorePanel.Visibility = Visibility.Collapsed;
        LoginPanel.Visibility = Visibility.Visible;
        ShowLoginStatus(message, true);
    }

    private async Task LoadStoresAsync()
    {
        if (_session is null) return;
        WorkspaceStatus.Text = "正在加载店铺";
        try
        {
            _allStores = await _api.GetStoresAsync(_session.AccessToken);
            ApplyStoreFilter();
            WorkspaceStatus.Text = _allStores.Count == 0
                ? "当前账号没有获授权店铺"
                : $"已加载 {_allStores.Count} 个店铺";
        }
        catch (ApiException error) when (error.StatusCode is 401 or 403)
        {
            WorkspaceStatus.Text = "会话已过期，请退出后重新登录";
        }
        catch
        {
            WorkspaceStatus.Text = "加载店铺失败，请稍后重试";
        }
    }

    private void ApplyStoreFilter()
    {
        var filtered = StoreFilter.Apply(_allStores, SearchBox.Text);
        _visibleStores.Clear();
        foreach (var store in filtered)
        {
            _visibleStores.Add(StoreRow.From(
                store,
                _processes.State(store.Id),
                _processes.EdgeLatencyMilliseconds(store.Id)));
        }
    }

    private void ShowLoginStatus(string message, bool isError)
    {
        StatusText.Text = message;
        StatusText.Foreground = new SolidColorBrush(
            isError ? Color.FromRgb(190, 35, 45) : Color.FromRgb(102, 115, 139));
    }

    private async void ExitApplication(object sender, RoutedEventArgs e)
    {
        await PrepareToCloseAsync();
    }

    private async void WindowClosing(object? sender, CancelEventArgs e)
    {
        if (_allowClose) return;
        e.Cancel = true;
        await PrepareToCloseAsync();
    }

    private async Task PrepareToCloseAsync()
    {
        if (_allowClose) return;
        IsEnabled = false;
        _refreshCancellation?.Cancel();
        await _processes.QuitAllAsync();
        _allowClose = true;
        Close();
    }

    private static string SafeLaunchError(Exception error) => error switch
    {
        FileNotFoundException file when file.FileName?.EndsWith("idengrid-agent.exe", StringComparison.OrdinalIgnoreCase) == true => "缺少内置Agent",
        FileNotFoundException => "缺少内置浏览器",
        TimeoutException => "Agent就绪超时",
        _ when error.Message.Contains("固定出口", StringComparison.Ordinal) => error.Message,
        _ => "网络或组件异常",
    };

}

public sealed class StoreRow
{
    public required StoreDto Store { get; init; }
    public string Id => Store.Id;
    public string Name => Store.Name;
    public required string NodeLine { get; init; }
    public required string StatusLine { get; init; }
    public required string LocalLatencyLine { get; init; }
    public required string StateLine { get; init; }
    public required Brush StateColor { get; init; }
    public required string LaunchButtonText { get; init; }
    public required bool IsLaunchEnabled { get; init; }
    public required bool IsCloseEnabled { get; init; }

    public static StoreRow From(
        StoreDto store,
        StoreRuntimeState runtime,
        long? edgeLatencyMilliseconds)
    {
        var ip = string.IsNullOrWhiteSpace(store.ExpectedPublicIpv4) ? "待配置" : store.ExpectedPublicIpv4;
        var reference = store.LatencyMs is double milliseconds ? $"中央节点参考 {milliseconds:0} ms" : "中央节点参考 --";
        var localLatency = edgeLatencyMilliseconds is long measured
            ? $"本机到实际Edge {measured} ms"
            : "本机到实际Edge --";
        var available = store.Enabled && store.HealthStatus == "online" && !store.MaintenanceMode;
        var stateLine = runtime switch
        {
            StoreRuntimeState.StartingAgent => "正在连接Agent",
            StoreRuntimeState.VerifyingEgress => "正在验证固定出口",
            StoreRuntimeState.LaunchingBrowser => "正在打开浏览器",
            StoreRuntimeState.Running => "运行中",
            StoreRuntimeState.Failed => "启动失败",
            _ => available ? "未运行" : "暂不可用",
        };
        var busy = runtime is StoreRuntimeState.StartingAgent or StoreRuntimeState.VerifyingEgress or StoreRuntimeState.LaunchingBrowser;
        return new StoreRow
        {
            Store = store,
            NodeLine = $"节点：{store.NodeName} · 固定IP：{ip}",
            StatusLine = reference,
            LocalLatencyLine = localLatency,
            StateLine = stateLine,
            StateColor = new SolidColorBrush(runtime == StoreRuntimeState.Running
                ? Color.FromRgb(40, 199, 183)
                : Color.FromRgb(160, 169, 185)),
            LaunchButtonText = runtime == StoreRuntimeState.Running ? "打开" : "启动",
            IsLaunchEnabled = runtime == StoreRuntimeState.Running || (available && !busy),
            IsCloseEnabled = runtime == StoreRuntimeState.Running,
        };
    }
}

internal static class DeviceIdentity
{
    public static string Current()
    {
        var root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "IdenGrid");
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "device-id.txt");
        if (File.Exists(path))
        {
            var existing = File.ReadAllText(path).Trim();
            if (Guid.TryParse(existing, out _)) return existing;
        }

        var value = Guid.NewGuid().ToString("D");
        File.WriteAllText(path, value);
        return value;
    }
}
