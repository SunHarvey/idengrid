using System.Collections.ObjectModel;
using IdenGrid.Core;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using WinRT.Interop;

namespace IdenGrid.Windows;

public sealed partial class MainWindow : Window
{
    private readonly NativeApiClient _api;
    private readonly ObservableCollection<StoreRow> _visibleStores = [];
    private IReadOnlyList<StoreDto> _allStores = [];
    private string? _accessToken;

    public ObservableCollection<StoreRow> VisibleStores => _visibleStores;

    public MainWindow()
    {
        InitializeComponent();
        var handler = new SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromSeconds(15),
        };
        var http = new HttpClient(handler)
        {
            BaseAddress = ApiBaseAddress(),
            Timeout = TimeSpan.FromSeconds(30),
        };
        _api = new NativeApiClient(http);

        var windowHandle = WindowNative.GetWindowHandle(this);
        var windowId = Win32Interop.GetWindowIdFromWindow(windowHandle);
        var appWindow = AppWindow.GetFromWindowId(windowId);
        appWindow.Resize(new global::Windows.Graphics.SizeInt32(1060, 700));
    }

    private async void LoginClick(object sender, RoutedEventArgs args)
    {
        var username = UsernameBox.Text.Trim();
        var password = PasswordBox.Password;
        if (username.Length == 0 || password.Length == 0)
        {
            ShowLoginStatus("请输入用户名和密码", isError: true);
            return;
        }

        LoginButton.IsEnabled = false;
        LoginButton.Content = "登录中…";
        ShowLoginStatus("正在连接", isError: false);
        try
        {
            var session = await _api.LoginAsync(
                username,
                password,
                DeviceIdentity.Current(),
                Environment.MachineName);
            _accessToken = session.AccessToken;
            await LoadStoresAsync();
            LoginPanel.Visibility = Visibility.Collapsed;
            StorePanel.Visibility = Visibility.Visible;
        }
        catch (ApiException error)
        {
            ShowLoginStatus(LoginPresentation.FailureMessage(error.StatusCode), isError: true);
        }
        catch
        {
            ShowLoginStatus(LoginPresentation.FailureMessage(null), isError: true);
        }
        finally
        {
            PasswordBox.Password = string.Empty;
            LoginButton.Content = "登录";
            LoginButton.IsEnabled = true;
        }
    }

    private async void RefreshClick(object sender, RoutedEventArgs args)
    {
        await LoadStoresAsync();
    }

    private void SearchChanged(object sender, TextChangedEventArgs args)
    {
        ApplyStoreFilter();
    }

    private void LogoutClick(object sender, RoutedEventArgs args)
    {
        _accessToken = null;
        _allStores = [];
        _visibleStores.Clear();
        SearchBox.Text = string.Empty;
        StorePanel.Visibility = Visibility.Collapsed;
        LoginPanel.Visibility = Visibility.Visible;
        ShowLoginStatus("已退出登录", isError: false);
    }

    private async Task LoadStoresAsync()
    {
        if (_accessToken is null) return;
        WorkspaceStatus.Text = "正在加载店铺";
        try
        {
            _allStores = await _api.GetStoresAsync(_accessToken);
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
        foreach (var store in filtered) _visibleStores.Add(StoreRow.From(store));
    }

    private void ShowLoginStatus(string message, bool isError)
    {
        StatusText.Text = message;
        StatusText.Foreground = new SolidColorBrush(isError ? Colors.Red : ColorHelper.FromArgb(255, 102, 115, 139));
    }

    private void ExitApplication(object sender, RoutedEventArgs args)
    {
        Close();
    }

    private static Uri ApiBaseAddress()
    {
        var configured = Environment.GetEnvironmentVariable("IDENGRID_API_BASE_URL");
        var value = string.IsNullOrWhiteSpace(configured)
            ? "https://api.example.com/"
            : configured;
        var uri = new Uri(value, UriKind.Absolute);
        if (uri.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new InvalidOperationException("IDENGRID_API_BASE_URL must be an HTTPS origin");
        }
        return uri;
    }
}

public sealed class StoreRow
{
    public string Name { get; set; } = string.Empty;
    public string NodeLine { get; set; } = string.Empty;
    public string StatusLine { get; set; } = string.Empty;

    public static StoreRow From(StoreDto store)
    {
        var ip = string.IsNullOrWhiteSpace(store.ExpectedPublicIpv4) ? "待配置" : store.ExpectedPublicIpv4;
        var state = store.Enabled && store.HealthStatus == "online" && !store.MaintenanceMode
            ? "可启动"
            : "暂不可用";
        var latency = store.LatencyMs is double milliseconds ? $" · 节点参考 {milliseconds:0} ms" : string.Empty;
        return new StoreRow
        {
            Name = store.Name,
            NodeLine = $"节点：{store.NodeName} · 固定IP：{ip}",
            StatusLine = $"状态：{state}{latency}",
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
