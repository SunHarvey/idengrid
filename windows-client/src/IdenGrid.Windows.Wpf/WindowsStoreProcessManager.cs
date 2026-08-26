using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using IdenGrid.Core;

namespace IdenGrid.Windows.Wpf;

public enum StoreRuntimeState
{
    Idle,
    StartingAgent,
    VerifyingEgress,
    LaunchingBrowser,
    Running,
    Failed,
}

public sealed class WindowsStoreProcessManager
{
    private readonly Dictionary<string, RunningStore> _running = [];
    private readonly Dictionary<string, StoreRuntimeState> _states = [];
    private readonly Dictionary<string, long?> _edgeLatencies = [];
    private readonly string _applicationRoot;
    private readonly Uri _centralUrl;
    private readonly string _deviceId;

    public event Action<string>? StateChanged;

    public WindowsStoreProcessManager(Uri centralUrl, string deviceId)
    {
        _centralUrl = centralUrl;
        _deviceId = deviceId;
        _applicationRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "IdenGrid");
    }

    public StoreRuntimeState State(string storeId) =>
        _states.GetValueOrDefault(storeId, StoreRuntimeState.Idle);

    public long? EdgeLatencyMilliseconds(string storeId) =>
        _edgeLatencies.GetValueOrDefault(storeId);

    public bool IsRunning(string storeId) => _running.ContainsKey(storeId);

    public async Task LaunchAsync(StoreDto store, string accessToken, CancellationToken cancellationToken = default)
    {
        if (_running.TryGetValue(store.Id, out var existing))
        {
            Activate(existing.Browser);
            return;
        }

        var storeRoot = Path.Combine(_applicationRoot, "Stores", $"store-{store.Id}");
        var runtime = Path.Combine(storeRoot, "Runtime");
        var downloads = Path.Combine(storeRoot, "Downloads");
        var profile = WindowsProfileLayout.UserDataDirectory(_applicationRoot, store.Id);
        Directory.CreateDirectory(runtime);
        Directory.CreateDirectory(downloads);
        Directory.CreateDirectory(profile);
        var extension = PrepareStoreExtension(store, storeRoot);

        var lockPath = Path.Combine(runtime, "store.lock");
        FileStream? lockHandle = null;
        Process? agent = null;
        Process? browser = null;
        CancellationTokenSource? identityCancellation = null;
        nint iconHandle = 0;
        var pipeName = $"IdenGrid-store-{store.Id}-{Guid.NewGuid():N}";
        var capability = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        try
        {
            lockHandle = new FileStream(lockPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            await lockHandle.WriteAsync(Encoding.ASCII.GetBytes($"{Environment.ProcessId}\n"), cancellationToken);
            await lockHandle.FlushAsync(cancellationToken);

            SetState(store.Id, StoreRuntimeState.StartingAgent);
            agent = StartAgent(store, accessToken, pipeName, capability);
            var status = await WaitForStatusAsync(pipeName, capability, TimeSpan.FromSeconds(25), cancellationToken);
            if (status.Status != "connected" || status.DeviceId != _deviceId ||
                status.SocksHost != "127.0.0.1" || status.SocksPort <= 0)
            {
                throw new InvalidOperationException("Agent状态无效");
            }

            SetState(store.Id, StoreRuntimeState.VerifyingEgress);
            await VerifyEgressAsync(status.SocksPort, store.ExpectedPublicIpv4, cancellationToken);

            SetState(store.Id, StoreRuntimeState.LaunchingBrowser);
            browser = StartBrowser(store, profile, downloads, extension, status.SocksPort);
            identityCancellation = new CancellationTokenSource();
            var iconPath = StoreTaskbarIcon.Create(storeRoot, store.Name, store.Id);
            iconHandle = LoadStoreIcon(iconPath);
            await WaitForMainWindowAsync(browser, TimeSpan.FromSeconds(12), cancellationToken);
            _ = MaintainBrowserIdentityAsync(
                browser,
                store.Name,
                iconHandle,
                identityCancellation.Token);
            var record = new RunningStore(
                store.Id,
                agent,
                browser,
                lockHandle,
                lockPath,
                pipeName,
                capability,
                identityCancellation,
                iconHandle);
            _running[store.Id] = record;
            agent.EnableRaisingEvents = true;
            browser.EnableRaisingEvents = true;
            agent.Exited += (_, _) => HandleUnexpectedExit(store.Id, "Agent 已意外退出");
            browser.Exited += (_, _) => HandleUnexpectedExit(store.Id, "浏览器已意外退出");
            SetState(store.Id, StoreRuntimeState.Running);
            _ = PollEdgeLatencyAsync(record, identityCancellation.Token);
        }
        catch
        {
            identityCancellation?.Cancel();
            if (browser is not null) await StopProcessAsync(browser, TimeSpan.FromSeconds(2));
            if (agent is not null) await StopProcessAsync(agent, TimeSpan.FromSeconds(2));
            if (iconHandle != 0) _ = DestroyIcon(iconHandle);
            identityCancellation?.Dispose();
            lockHandle?.Dispose();
            TryDelete(lockPath);
            SetState(store.Id, StoreRuntimeState.Failed);
            throw;
        }
    }

    public async Task CloseAsync(string storeId)
    {
        if (!_running.Remove(storeId, out var record))
        {
            SetState(storeId, StoreRuntimeState.Idle);
            return;
        }

        record.Agent.EnableRaisingEvents = false;
        record.Browser.EnableRaisingEvents = false;
        record.IdentityCancellation.Cancel();
        await StopBrowserAsync(record.Browser);
        await RequestAsync(record.PipeName, record.Capability, "shutdown", CancellationToken.None)
            .ContinueWith(_ => { }, TaskScheduler.Default);
        await StopProcessAsync(record.Agent, TimeSpan.FromSeconds(3));
        record.LockHandle.Dispose();
        if (record.IconHandle != 0) _ = DestroyIcon(record.IconHandle);
        record.IdentityCancellation.Dispose();
        TryDelete(record.LockPath);
        _edgeLatencies.Remove(storeId);
        SetState(storeId, StoreRuntimeState.Idle);
    }

    public async Task QuitAllAsync()
    {
        foreach (var storeId in _running.Keys.ToArray()) await CloseAsync(storeId);
    }

    public async Task UpdateAccessTokenAsync(string nativeAccessToken)
    {
        var failed = new List<string>();
        foreach (var record in _running.Values.ToArray())
        {
            try
            {
                _ = await RequestAsync(
                    record.PipeName,
                    record.Capability,
                    "update_token",
                    CancellationToken.None,
                    nativeAccessToken);
            }
            catch
            {
                failed.Add(record.StoreId);
            }
        }

        foreach (var storeId in failed) await CloseAsync(storeId);
        if (failed.Count > 0)
            throw new InvalidOperationException("部分运行中店铺无法更新会话，已安全关闭");
    }

    public void Activate(string storeId)
    {
        if (_running.TryGetValue(storeId, out var record)) Activate(record.Browser);
    }

    private static string PrepareStoreExtension(StoreDto store, string storeRoot)
    {
        var bundled = Path.Combine(AppContext.BaseDirectory, "Components", "Extension");
        if (!File.Exists(Path.Combine(bundled, "manifest.json")))
            throw new FileNotFoundException("缺少内置隐私扩展");
        if (string.IsNullOrWhiteSpace(store.ExpectedPublicIpv4))
            throw new InvalidOperationException("店铺未配置固定出口IP");

        var destination = Path.Combine(storeRoot, "Extension");
        var staging = destination + ".staging-" + Guid.NewGuid().ToString("N");
        Directory.CreateDirectory(staging);
        try
        {
            foreach (var source in Directory.EnumerateFiles(bundled))
            {
                if (string.Equals(Path.GetFileName(source), "identity.json", StringComparison.OrdinalIgnoreCase))
                    continue;
                File.Copy(source, Path.Combine(staging, Path.GetFileName(source)), true);
            }
            var identity = new
            {
                store_name = store.Name,
                short_label = StoreTaskbarIcon.LabelFor(store.Name, store.Id),
                node_name = store.NodeName,
                fixed_ip = store.ExpectedPublicIpv4,
                color = StoreTaskbarIcon.ColorFor(store.Id),
            };
            File.WriteAllBytes(
                Path.Combine(staging, "identity.json"),
                JsonSerializer.SerializeToUtf8Bytes(identity));
            if (Directory.Exists(destination)) Directory.Delete(destination, true);
            Directory.Move(staging, destination);
            return destination;
        }
        catch
        {
            if (Directory.Exists(staging)) Directory.Delete(staging, true);
            throw;
        }
    }

    private Process StartAgent(StoreDto store, string accessToken, string pipeName, string capability)
    {
        var executable = ResolveExecutable(
            "IDENGRID_AGENT_PATH",
            Path.Combine(AppContext.BaseDirectory, "Components", "idengrid-agent.exe"),
            "缺少内置Agent");
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = false,
            RedirectStandardError = false,
        };
        var process = Process.Start(start) ?? throw new InvalidOperationException("无法启动Agent");
        var config = new
        {
            central_url = _centralUrl.AbsoluteUri,
            native_access_token = accessToken,
            store_id = ulong.Parse(store.Id),
            device_id = _deviceId,
            control_socket_path = $@"\\.\pipe\{pipeName}",
            control_capability = capability,
            local_port = 0,
        };
        process.StandardInput.Write(JsonSerializer.Serialize(config));
        process.StandardInput.Close();
        return process;
    }

    private Process StartBrowser(
        StoreDto store,
        string profile,
        string downloads,
        string extension,
        int socksPort)
    {
        var executable = ResolveExecutable(
            "IDENGRID_CHROMIUM_PATH",
            Path.Combine(AppContext.BaseDirectory, "Components", "Browser", "chrome.exe"),
            "缺少内置浏览器");
        var start = new ProcessStartInfo(executable) { UseShellExecute = false };
        start.ArgumentList.Add($"--user-data-dir={profile}");
        start.ArgumentList.Add($"--downloads-path={downloads}");
        start.ArgumentList.Add($"--proxy-server=socks5://127.0.0.1:{socksPort}");
        start.ArgumentList.Add("--proxy-bypass-list=<-loopback>");
        start.ArgumentList.Add($"--load-extension={extension}");
        start.ArgumentList.Add($"--disable-extensions-except={extension}");
        start.ArgumentList.Add("--disable-quic");
        start.ArgumentList.Add("--webrtc-ip-handling-policy=disable_non_proxied_udp");
        start.ArgumentList.Add("--no-first-run");
        start.ArgumentList.Add("--no-default-browser-check");
        start.ArgumentList.Add("--disable-sync");
        return Process.Start(start) ?? throw new InvalidOperationException($"无法启动{store.Name}浏览器");
    }

    private static async Task VerifyEgressAsync(
        int socksPort,
        string? expectedPublicIpv4,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(expectedPublicIpv4))
            throw new InvalidOperationException("店铺未配置固定出口IP");
        using var handler = new SocketsHttpHandler
        {
            Proxy = new WebProxy(new Uri($"socks5://127.0.0.1:{socksPort}")),
            UseProxy = true,
            ConnectTimeout = TimeSpan.FromSeconds(15),
        };
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
        var actual = (await http.GetStringAsync("https://api.ipify.org", cancellationToken)).Trim();
        if (!string.Equals(actual, expectedPublicIpv4, StringComparison.Ordinal))
            throw new InvalidOperationException("固定出口IP验证失败");
    }

    private static async Task<AgentStatus> WaitForStatusAsync(
        string pipeName,
        string capability,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        Exception? last = null;
        while (DateTimeOffset.UtcNow < deadline)
        {
            try
            {
                return await RequestAsync(pipeName, capability, "status", cancellationToken);
            }
            catch (Exception error) when (error is IOException or TimeoutException)
            {
                last = error;
                await Task.Delay(250, cancellationToken);
            }
        }
        throw new TimeoutException("Agent就绪超时", last);
    }

    private static async Task<AgentStatus> RequestAsync(
        string pipeName,
        string capability,
        string command,
        CancellationToken cancellationToken,
        string? nativeAccessToken = null)
    {
        await using var pipe = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous);
        await pipe.ConnectAsync(1000, cancellationToken);
        object payload = nativeAccessToken is null
            ? new { capability, command }
            : new { capability, command, native_access_token = nativeAccessToken };
        var request = JsonSerializer.Serialize(payload) + "\n";
        var bytes = Encoding.UTF8.GetBytes(request);
        await pipe.WriteAsync(bytes, cancellationToken);
        await pipe.FlushAsync(cancellationToken);
        using var reader = new StreamReader(pipe, Encoding.UTF8, false, leaveOpen: true);
        var line = await reader.ReadLineAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(line)) throw new IOException("Agent没有返回状态");
        return JsonSerializer.Deserialize<AgentStatus>(line)
            ?? throw new IOException("Agent状态JSON无效");
    }

    private async Task PollEdgeLatencyAsync(
        RunningStore record,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
                var status = await RequestAsync(
                    record.PipeName,
                    record.Capability,
                    "status",
                    cancellationToken);
                var latency = status.EdgeLatency;
                _edgeLatencies[record.StoreId] = latency is not null
                    && latency.Source == "websocket_ping"
                    && latency.State is "fresh" or "degraded"
                        ? latency.EwmaRttMs ?? latency.LatestRttMs
                        : null;
                StateChanged?.Invoke(record.StoreId);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (IOException)
            {
                _edgeLatencies[record.StoreId] = null;
                StateChanged?.Invoke(record.StoreId);
            }
            catch (TimeoutException)
            {
                _edgeLatencies[record.StoreId] = null;
                StateChanged?.Invoke(record.StoreId);
            }
        }
    }

    private async void HandleUnexpectedExit(string storeId, string reason)
    {
        if (!_running.Remove(storeId, out var record)) return;
        record.IdentityCancellation.Cancel();
        await StopProcessAsync(record.Browser, TimeSpan.FromSeconds(1));
        await StopProcessAsync(record.Agent, TimeSpan.FromSeconds(1));
        record.LockHandle.Dispose();
        if (record.IconHandle != 0) _ = DestroyIcon(record.IconHandle);
        record.IdentityCancellation.Dispose();
        TryDelete(record.LockPath);
        _edgeLatencies.Remove(storeId);
        SetState(storeId, StoreRuntimeState.Failed);
        _ = reason;
    }

    private void SetState(string storeId, StoreRuntimeState state)
    {
        _states[storeId] = state;
        StateChanged?.Invoke(storeId);
    }

    private static async Task StopBrowserAsync(Process process)
    {
        if (process.HasExited) return;
        _ = process.CloseMainWindow();
        if (await WaitForExitAsync(process, TimeSpan.FromSeconds(5))) return;
        process.Kill(true);
        await WaitForExitAsync(process, TimeSpan.FromSeconds(3));
    }

    private static async Task StopProcessAsync(Process process, TimeSpan timeout)
    {
        if (process.HasExited) return;
        if (await WaitForExitAsync(process, timeout)) return;
        process.Kill(true);
        await WaitForExitAsync(process, TimeSpan.FromSeconds(2));
    }

    private static async Task<bool> WaitForExitAsync(Process process, TimeSpan timeout)
    {
        using var cancellation = new CancellationTokenSource(timeout);
        try { await process.WaitForExitAsync(cancellation.Token); return true; }
        catch (OperationCanceledException) { return process.HasExited; }
    }

    private static string ResolveExecutable(string environmentName, string fallback, string error)
    {
        var configured = Environment.GetEnvironmentVariable(environmentName);
        var path = string.IsNullOrWhiteSpace(configured) ? fallback : configured;
        if (!File.Exists(path)) throw new FileNotFoundException(error, path);
        return Path.GetFullPath(path);
    }

    private static void Activate(Process process)
    {
        if (process.HasExited) return;
        _ = ShowWindow(process.MainWindowHandle, 9);
        _ = SetForegroundWindow(process.MainWindowHandle);
    }

    private static async Task WaitForMainWindowAsync(
        Process process,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (process.HasExited) throw new InvalidOperationException("浏览器已意外退出");
            process.Refresh();
            if (process.MainWindowHandle != 0) return;
            await Task.Delay(100, cancellationToken);
        }
        throw new TimeoutException("浏览器窗口就绪超时");
    }

    private static async Task MaintainBrowserIdentityAsync(
        Process process,
        string storeName,
        nint iconHandle,
        CancellationToken cancellationToken)
    {
        var title = $"{storeName} · IdenGrid";
        while (!cancellationToken.IsCancellationRequested && !process.HasExited)
        {
            process.Refresh();
            var window = process.MainWindowHandle;
            if (window != 0)
            {
                _ = SetWindowText(window, title);
                if (iconHandle != 0)
                {
                    _ = SendMessage(window, WM_SETICON, ICON_SMALL, iconHandle);
                    _ = SendMessage(window, WM_SETICON, ICON_BIG, iconHandle);
                }
            }
            try { await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken); }
            catch (OperationCanceledException) { return; }
        }
    }

    private static nint LoadStoreIcon(string iconPath) =>
        File.Exists(iconPath)
            ? LoadImage(0, iconPath, IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE)
            : 0;

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch (IOException) { }
    }

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(nint windowHandle);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(nint windowHandle, int command);

    private const uint WM_SETICON = 0x0080;
    private const nint ICON_SMALL = 0;
    private const nint ICON_BIG = 1;
    private const uint IMAGE_ICON = 1;
    private const uint LR_LOADFROMFILE = 0x0010;
    private const uint LR_DEFAULTSIZE = 0x0040;

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetWindowText(nint windowHandle, string text);

    [DllImport("user32.dll")]
    private static extern nint SendMessage(nint windowHandle, uint message, nint wParam, nint lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint LoadImage(
        nint instance,
        string name,
        uint type,
        int desiredWidth,
        int desiredHeight,
        uint loadFlags);

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(nint iconHandle);

    private sealed record RunningStore(
        string StoreId,
        Process Agent,
        Process Browser,
        FileStream LockHandle,
        string LockPath,
        string PipeName,
        string Capability,
        CancellationTokenSource IdentityCancellation,
        nint IconHandle);

    private sealed record AgentStatus(
        [property: JsonPropertyName("status")] string Status,
        [property: JsonPropertyName("socks_host")] string SocksHost,
        [property: JsonPropertyName("socks_port")] int SocksPort,
        [property: JsonPropertyName("store_id")] ulong StoreId,
        [property: JsonPropertyName("device_id")] string DeviceId,
        [property: JsonPropertyName("edge_latency")] EdgeLatencyStatus? EdgeLatency);

    private sealed record EdgeLatencyStatus(
        [property: JsonPropertyName("source")] string Source,
        [property: JsonPropertyName("state")] string State,
        [property: JsonPropertyName("latest_rtt_ms")] long? LatestRttMs,
        [property: JsonPropertyName("ewma_rtt_ms")] long? EwmaRttMs);
}
