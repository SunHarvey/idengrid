using System.Collections.Concurrent;
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
using System.Text.Json.Nodes;
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
    private readonly ConcurrentDictionary<string, StartingStore> _starting = [];
    private readonly ConcurrentDictionary<string, RunningStore> _running = [];
    private readonly ConcurrentDictionary<string, StoreRuntimeState> _states = [];
    private readonly ConcurrentDictionary<string, long?> _edgeLatencies = [];
    private readonly SemaphoreSlim _launchRegistrationGate = new(1, 1);
    private int _drainingLaunches;
    private long _drainGeneration;
    private readonly string _applicationRoot;
    private readonly Uri _centralUrl;
    private readonly string _deviceId;
    private readonly bool _braveAdBlockOnlyMode;

    public event Action<string>? StateChanged;

    public WindowsStoreProcessManager(
        Uri centralUrl,
        string deviceId,
        bool braveAdBlockOnlyMode = false)
    {
        _centralUrl = centralUrl;
        _deviceId = deviceId;
        _braveAdBlockOnlyMode = braveAdBlockOnlyMode;
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
        cancellationToken.ThrowIfCancellationRequested();
        var observedDrainGeneration = Volatile.Read(ref _drainGeneration);
        if (Volatile.Read(ref _drainingLaunches) != 0)
            throw new InvalidOperationException("正在关闭全部店铺，无法启动新店铺");
        while (_running.TryGetValue(store.Id, out var existing))
        {
            var activateExisting = false;
            lock (existing.LifecycleGate)
            {
                activateExisting = !existing.CleanupClaimed
                    && !existing.Agent.HasExited
                    && !existing.Browser.HasExited;
            }
            if (activateExisting)
            {
                Activate(existing.Browser);
                return;
            }
            if (!existing.CleanupClaimed)
                HandleUnexpectedExit(existing, "店铺进程已意外退出");
            await existing.CleanupCompletion.Task.WaitAsync(cancellationToken);
        }

        StartingStore candidateStartup;
        StartingStore startup;
        await _launchRegistrationGate.WaitAsync(cancellationToken);
        try
        {
            if (Volatile.Read(ref _drainingLaunches) != 0
                || Volatile.Read(ref _drainGeneration) != observedDrainGeneration)
                throw new InvalidOperationException("关闭全部店铺期间的启动请求已取消");
            candidateStartup = new StartingStore(cancellationToken);
            startup = _starting.GetOrAdd(store.Id, candidateStartup);
        }
        finally
        {
            _launchRegistrationGate.Release();
        }
        if (!ReferenceEquals(startup, candidateStartup))
        {
            candidateStartup.Dispose();
            await startup.Completion.Task.WaitAsync(cancellationToken);
            var startedRecord = startup.RunningRecord;
            if (startedRecord is null)
                throw new InvalidOperationException("店铺启动未成功");
            lock (startedRecord.LifecycleGate)
            {
                if (!_running.TryGetValue(store.Id, out var registered)
                    || !ReferenceEquals(registered, startedRecord)
                    || startedRecord.CleanupClaimed
                    || startedRecord.Agent.HasExited
                    || startedRecord.Browser.HasExited)
                    throw new InvalidOperationException("店铺启动未能保持运行");
            }
            Activate(startedRecord.Browser);
            return;
        }

        try
        {
            await LaunchOwnedAsync(store, accessToken, startup);
        }
        finally
        {
            try
            {
                ((ICollection<KeyValuePair<string, StartingStore>>)_starting).Remove(
                    new KeyValuePair<string, StartingStore>(store.Id, startup));
            }
            finally
            {
                startup.Completion.TrySetResult();
                startup.Dispose();
            }
        }
    }

    private async Task LaunchOwnedAsync(StoreDto store, string accessToken, StartingStore startup)
    {
        var cancellationToken = startup.Cancellation.Token;
        startup.Cancellation.Token.ThrowIfCancellationRequested();
        var storeRoot = Path.Combine(_applicationRoot, "Stores", $"store-{store.Id}");
        var runtime = Path.Combine(storeRoot, "Runtime");
        var downloads = Path.Combine(storeRoot, "Downloads");
        var profile = WindowsProfileLayout.UserDataDirectory(_applicationRoot, store.Id);
        startup.Cancellation.Token.ThrowIfCancellationRequested();
        Directory.CreateDirectory(runtime);
        startup.Cancellation.Token.ThrowIfCancellationRequested();
        Directory.CreateDirectory(downloads);
        startup.Cancellation.Token.ThrowIfCancellationRequested();
        Directory.CreateDirectory(profile);
        startup.Cancellation.Token.ThrowIfCancellationRequested();
        var extension = PrepareStoreExtension(store, storeRoot);

        var lockPath = Path.Combine(runtime, "store.lock");
        FileStream? lockHandle = null;
        Process? agent = null;
        Process? browser = null;
        CancellationTokenSource? identityCancellation = null;
        nint iconHandle = 0;
        RunningStore? record = null;
        var pipeName = $"IdenGrid-store-{store.Id}-{Guid.NewGuid():N}";
        var capability = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        try
        {
            startup.Cancellation.Token.ThrowIfCancellationRequested();
            lockHandle = new FileStream(lockPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            await lockHandle.WriteAsync(Encoding.ASCII.GetBytes($"{Environment.ProcessId}\n"), cancellationToken);
            await lockHandle.FlushAsync(cancellationToken);

            startup.Cancellation.Token.ThrowIfCancellationRequested();
            SetState(store.Id, StoreRuntimeState.StartingAgent);
            startup.Cancellation.Token.ThrowIfCancellationRequested();
            agent = StartAgent(store, accessToken, pipeName, capability);
            var status = await WaitForStatusAsync(pipeName, capability, TimeSpan.FromSeconds(25), cancellationToken);
            if (status.Status != "connected" || status.DeviceId != _deviceId ||
                status.SocksHost != "127.0.0.1" || status.SocksPort <= 0)
            {
                throw new InvalidOperationException("Agent状态无效");
            }

            startup.Cancellation.Token.ThrowIfCancellationRequested();
            SetState(store.Id, StoreRuntimeState.VerifyingEgress);
            await VerifyEgressAsync(status.SocksPort, store.ExpectedPublicIpv4, cancellationToken);

            startup.Cancellation.Token.ThrowIfCancellationRequested();
            SetState(store.Id, StoreRuntimeState.LaunchingBrowser);
            startup.Cancellation.Token.ThrowIfCancellationRequested();
            browser = StartBrowser(store, profile, downloads, extension, status.SocksPort);
            identityCancellation = new CancellationTokenSource();
            startup.Cancellation.Token.ThrowIfCancellationRequested();
            var iconPath = StoreTaskbarIcon.Create(storeRoot, store.Name, store.Id);
            iconHandle = LoadStoreIcon(iconPath);
            await WaitForMainWindowAsync(browser, TimeSpan.FromSeconds(12), cancellationToken);
            startup.Cancellation.Token.ThrowIfCancellationRequested();
            _ = MaintainBrowserIdentityAsync(
                browser,
                store.Name,
                iconHandle,
                identityCancellation.Token);
            var runningRecord = new RunningStore(
                store.Id,
                agent,
                browser,
                lockHandle,
                lockPath,
                pipeName,
                capability,
                identityCancellation,
                iconHandle);
            record = runningRecord;
            agent.Exited += (_, _) => HandleUnexpectedExit(runningRecord, "Agent 已意外退出");
            browser.Exited += (_, _) => HandleUnexpectedExit(runningRecord, "浏览器已意外退出");
            startup.Cancellation.Token.ThrowIfCancellationRequested();
            if (!_running.TryAdd(store.Id, runningRecord))
                throw new InvalidOperationException("店铺已在运行");
            startup.Cancellation.Token.ThrowIfCancellationRequested();
            agent.EnableRaisingEvents = true;
            startup.Cancellation.Token.ThrowIfCancellationRequested();
            browser.EnableRaisingEvents = true;
            lock (runningRecord.LifecycleGate)
            {
                startup.Cancellation.Token.ThrowIfCancellationRequested();
                if (!_running.TryGetValue(store.Id, out var registered)
                    || !ReferenceEquals(registered, runningRecord)
                    || runningRecord.CleanupClaimed
                    || agent.HasExited
                    || browser.HasExited)
                    throw new InvalidOperationException("店铺进程未能保持运行");
                _states[store.Id] = StoreRuntimeState.Running;
                startup.RunningRecord = runningRecord;
            }
            StateChanged?.Invoke(store.Id);
            _ = PollEdgeLatencyAsync(runningRecord, identityCancellation.Token);
        }
        catch (Exception error)
        {
            WriteLaunchDiagnostic(store.Id, State(store.Id), error);
            if (record is not null)
            {
                if (TryClaimCleanup(record))
                {
                    try
                    {
                        try { record.Agent.EnableRaisingEvents = false; } catch { }
                        try { record.Browser.EnableRaisingEvents = false; } catch { }
                        try { record.IdentityCancellation.Cancel(); } catch { }
                        try { await StopBrowserAsync(record.Browser); } catch { }
                        try { await StopProcessAsync(record.Agent, TimeSpan.FromSeconds(2)); } catch { }
                    }
                    finally
                    {
                        CleanupRecord(record, StoreRuntimeState.Failed);
                    }
                }
                else
                {
                    await record.CleanupCompletion.Task;
                }
            }
            else
            {
                try
                {
                    try { identityCancellation?.Cancel(); } catch { }
                    if (browser is not null)
                    {
                        try { await StopBrowserAsync(browser); } catch { }
                    }
                    if (agent is not null)
                    {
                        try { await StopProcessAsync(agent, TimeSpan.FromSeconds(2)); } catch { }
                    }
                }
                finally
                {
                    if (iconHandle != 0)
                    {
                        try { _ = DestroyIcon(iconHandle); } catch { }
                    }
                    try { identityCancellation?.Dispose(); } catch { }
                    try { lockHandle?.Dispose(); } catch { }
                    TryDelete(lockPath);
                    SetState(store.Id, StoreRuntimeState.Failed);
                }
            }
            throw;
        }
    }

    public async Task CloseAsync(string storeId)
    {
        var closeSlot = new StartingStore(CancellationToken.None);
        try
        {
            while (true)
            {
                var startup = _starting.GetOrAdd(storeId, closeSlot);
                if (ReferenceEquals(startup, closeSlot)) break;
                try { startup.Cancellation.Cancel(); }
                catch (ObjectDisposedException) { }
                await startup.Completion.Task;
            }

            await CloseRunningAsync(storeId);
        }
        finally
        {
            try
            {
                ((ICollection<KeyValuePair<string, StartingStore>>)_starting).Remove(
                    new KeyValuePair<string, StartingStore>(storeId, closeSlot));
            }
            finally
            {
                closeSlot.Completion.TrySetResult();
                closeSlot.Dispose();
            }
        }
    }

    private async Task CloseRunningAsync(string storeId)
    {
        if (!_running.TryGetValue(storeId, out var record))
        {
            SetState(storeId, StoreRuntimeState.Idle);
            return;
        }

        if (!TryClaimCleanup(record))
        {
            await record.CleanupCompletion.Task;
            return;
        }

        Exception? stopError = null;
        try
        {
            try { record.Agent.EnableRaisingEvents = false; } catch { }
            try { record.Browser.EnableRaisingEvents = false; } catch { }
            try { record.IdentityCancellation.Cancel(); } catch { }
            try { await StopBrowserAsync(record.Browser); }
            catch (Exception error) { stopError = error; }
            try
            {
                _ = await RequestAsync(record.PipeName, record.Capability, "shutdown", CancellationToken.None);
            }
            catch { }
            try { await StopProcessAsync(record.Agent, TimeSpan.FromSeconds(3)); }
            catch (Exception error) { stopError ??= error; }
        }
        finally
        {
            CleanupRecord(record, StoreRuntimeState.Idle);
        }
        if (stopError is not null) throw stopError;
    }

    public async Task QuitAllAsync()
    {
        await _launchRegistrationGate.WaitAsync();
        Interlocked.Increment(ref _drainGeneration);
        Volatile.Write(ref _drainingLaunches, 1);
        try
        {
            var storeIds = _starting.Keys.Union(_running.Keys).Distinct().ToArray();
            foreach (var storeId in storeIds) await CloseAsync(storeId);
        }
        finally
        {
            Volatile.Write(ref _drainingLaunches, 0);
            _launchRegistrationGate.Release();
        }
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
        ConfigureBrowserProfile(profile, downloads, _braveAdBlockOnlyMode);
        var executable = ResolveBrowserExecutable();
        var start = new ProcessStartInfo(executable) { UseShellExecute = false };
        start.ArgumentList.Add($"--user-data-dir={profile}");
        start.ArgumentList.Add($"--proxy-server=socks5://127.0.0.1:{socksPort}");
        start.ArgumentList.Add("--proxy-bypass-list=<-loopback>");
        start.ArgumentList.Add($"--load-extension={extension}");
        start.ArgumentList.Add($"--disable-extensions-except={extension}");
        start.ArgumentList.Add("--disable-quic");
        start.ArgumentList.Add("--webrtc-ip-handling-policy=disable_non_proxied_udp");
        start.ArgumentList.Add("--no-first-run");
        start.ArgumentList.Add("--no-default-browser-check");
        start.ArgumentList.Add("--disable-sync");
        start.ArgumentList.Add("--disable-background-mode");
        start.ArgumentList.Add("--restore-last-session");
        if (_braveAdBlockOnlyMode)
            start.ArgumentList.Add("--enable-features=AdblockOnlyMode");
        return Process.Start(start) ?? throw new InvalidOperationException($"无法启动{store.Name}浏览器");
    }

    private static void ConfigureBrowserProfile(
        string profile,
        string downloads,
        bool braveAdBlockOnlyMode)
    {
        var defaultProfile = Path.Combine(profile, "Default");
        Directory.CreateDirectory(defaultProfile);
        Directory.CreateDirectory(downloads);
        var preferencesPath = Path.Combine(defaultProfile, "Preferences");
        JsonObject preferences = File.Exists(preferencesPath)
            ? JsonNode.Parse(File.ReadAllText(preferencesPath))?.AsObject() ?? new JsonObject()
            : new JsonObject();
        var download = preferences["download"] as JsonObject ?? new JsonObject();
        download["default_directory"] = Path.GetFullPath(downloads);
        download["prompt_for_download"] = false;
        download["directory_upgrade"] = true;
        preferences["download"] = download;
        var savefile = preferences["savefile"] as JsonObject ?? new JsonObject();
        savefile["default_directory"] = Path.GetFullPath(downloads);
        preferences["savefile"] = savefile;
        var session = preferences["session"] as JsonObject ?? new JsonObject();
        session["restore_on_startup"] = 1;
        preferences["session"] = session;
        var backgroundMode = preferences["background_mode"] as JsonObject ?? new JsonObject();
        backgroundMode["enabled"] = false;
        backgroundMode["enabled_on_next_startup"] = false;
        preferences["background_mode"] = backgroundMode;
        var brave = preferences["brave"] as JsonObject ?? new JsonObject();
        brave["enable_window_closing_confirm"] = false;
        preferences["brave"] = brave;
        var stagingPath = preferencesPath + ".idengrid-staging";
        File.WriteAllText(stagingPath, preferences.ToJsonString());
        File.Move(stagingPath, preferencesPath, true);
        ConfigureBrowserLocalState(profile, braveAdBlockOnlyMode);
    }

    private static void ConfigureBrowserLocalState(string profile, bool braveAdBlockOnlyMode)
    {
        var localStatePath = Path.Combine(profile, "Local State");
        JsonObject localState = File.Exists(localStatePath)
            ? JsonNode.Parse(File.ReadAllText(localStatePath))?.AsObject() ?? new JsonObject()
            : new JsonObject();
        var brave = localState["brave"] as JsonObject ?? new JsonObject();
        var p3a = brave["p3a"] as JsonObject ?? new JsonObject();
        p3a["enabled"] = false;
        p3a["notice_acknowledged"] = true;
        brave["p3a"] = p3a;
        if (braveAdBlockOnlyMode)
        {
            var shields = brave["shields"] as JsonObject ?? new JsonObject();
            shields["adblock_only_mode_enabled"] = true;
            brave["shields"] = shields;
        }
        brave["dont_ask_for_crash_reporting"] = true;
        localState["brave"] = brave;
        var metrics = localState["user_experience_metrics"] as JsonObject ?? new JsonObject();
        metrics["reporting_enabled"] = false;
        localState["user_experience_metrics"] = metrics;
        var stagingPath = localStatePath + ".idengrid-staging";
        File.WriteAllText(stagingPath, localState.ToJsonString());
        File.Move(stagingPath, localStatePath, true);
    }

    private static string ResolveBrowserExecutable()
    {
        var configured = Environment.GetEnvironmentVariable("IDENGRID_BROWSER_PATH");
        if (string.IsNullOrWhiteSpace(configured))
            configured = Environment.GetEnvironmentVariable("IDENGRID_CHROMIUM_PATH");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            if (!File.Exists(configured)) throw new FileNotFoundException("缺少已配置浏览器", configured);
            return Path.GetFullPath(configured);
        }

        var runtime = Path.Combine(AppContext.BaseDirectory, "Components", "Browser");
        var manifestPath = Path.Combine(runtime, "idengrid-runtime-manifest.json");
        if (File.Exists(manifestPath))
        {
            using var manifest = JsonDocument.Parse(File.ReadAllText(manifestPath));
            var executableName = manifest.RootElement.GetProperty("browser_executable").GetString();
            if (string.IsNullOrWhiteSpace(executableName) || Path.GetFileName(executableName) != executableName)
                throw new InvalidDataException("浏览器运行时清单中的可执行文件名无效");
            var declared = Path.Combine(runtime, executableName);
            if (!File.Exists(declared)) throw new FileNotFoundException("缺少清单声明的浏览器", declared);
            return Path.GetFullPath(declared);
        }

        return ResolveExecutable(
            "IDENGRID_CHROMIUM_PATH",
            Path.Combine(runtime, "chrome.exe"),
            "缺少内置浏览器");
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
                if (!PublishEdgeLatency(record, latency is not null
                    && latency.Source == "websocket_ping"
                    && latency.State is "fresh" or "degraded"
                        ? latency.EwmaRttMs ?? latency.LatestRttMs
                        : null))
                    return;
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (IOException)
            {
                if (!PublishEdgeLatency(record, null)) return;
            }
            catch (TimeoutException)
            {
                if (!PublishEdgeLatency(record, null)) return;
            }
        }
    }

    private bool PublishEdgeLatency(RunningStore record, long? latency)
    {
        lock (record.LifecycleGate)
        {
            if (record.CleanupClaimed
                || !_running.TryGetValue(record.StoreId, out var registered)
                || !ReferenceEquals(registered, record))
                return false;
            _edgeLatencies[record.StoreId] = latency;
        }
        StateChanged?.Invoke(record.StoreId);
        return true;
    }

    private async void HandleUnexpectedExit(RunningStore record, string reason)
    {
        try
        {
            if (!TryClaimCleanup(record)) return;
            try
            {
                try { record.IdentityCancellation.Cancel(); } catch { }
                try { await StopBrowserAsync(record.Browser); } catch { }
                try { await StopProcessAsync(record.Agent, TimeSpan.FromSeconds(1)); } catch { }
            }
            finally
            {
                CleanupRecord(record, StoreRuntimeState.Failed);
                _ = reason;
            }
        }
        catch { } // Async-void process event handlers must never leak exceptions.
    }

    private static bool TryClaimCleanup(RunningStore record)
    {
        lock (record.LifecycleGate)
        {
            return record.TryClaimCleanup();
        }
    }

    private void CleanupRecord(RunningStore record, StoreRuntimeState finalState)
    {
        try
        {
            try { record.LockHandle.Dispose(); } catch { }
            if (record.IconHandle != 0)
            {
                try { _ = DestroyIcon(record.IconHandle); } catch { }
            }
            try { record.IdentityCancellation.Dispose(); } catch { }
            TryDelete(record.LockPath);
            _edgeLatencies.TryRemove(record.StoreId, out _);
            _states[record.StoreId] = finalState;
            try { StateChanged?.Invoke(record.StoreId); } catch { }
        }
        finally
        {
            ((ICollection<KeyValuePair<string, RunningStore>>)_running).Remove(
                new KeyValuePair<string, RunningStore>(record.StoreId, record));
            record.CleanupCompletion.TrySetResult();
        }
    }

    private void SetState(string storeId, StoreRuntimeState state)
    {
        _states[storeId] = state;
        StateChanged?.Invoke(storeId);
    }

    private static async Task StopBrowserAsync(Process process)
    {
        if (process.HasExited) return;
        if (CloseBrowserWindows(process) == 0) _ = process.CloseMainWindow();
        if (await WaitForExitAsync(process, TimeSpan.FromSeconds(10))) return;
        process.Kill(true);
        await WaitForExitAsync(process, TimeSpan.FromSeconds(3));
    }

    private static int CloseBrowserWindows(Process process)
    {
        process.Refresh();
        if (process.HasExited) return 0;
        var processId = (uint)process.Id;
        var windows = new List<nint>();
        _ = EnumWindows((windowHandle, lParam) =>
        {
            _ = lParam;
            _ = GetWindowThreadProcessId(windowHandle, out var windowProcessId);
            if (windowProcessId == processId && IsWindowVisible(windowHandle))
                windows.Add(windowHandle);
            return true;
        }, 0);
        var sent = 0;
        foreach (var windowHandle in windows)
            if (PostMessage(windowHandle, WM_CLOSE, 0, 0)) sent++;
        return sent;
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

    private void WriteLaunchDiagnostic(string storeId, StoreRuntimeState phase, Exception error)
    {
        try
        {
            var directory = Path.Combine(_applicationRoot, "Logs");
            Directory.CreateDirectory(directory);
            var entry = JsonSerializer.Serialize(new
            {
                timestamp_utc = DateTimeOffset.UtcNow,
                store_id = storeId,
                phase = phase.ToString(),
                exception_type = error.GetType().FullName,
                message = error.Message,
                inner_exception_type = error.InnerException?.GetType().FullName,
                inner_message = error.InnerException?.Message,
            });
            File.AppendAllText(Path.Combine(directory, "client-launch.jsonl"), entry + Environment.NewLine);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(nint windowHandle);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(nint windowHandle, int command);

    private delegate bool EnumWindowsCallback(nint windowHandle, nint lParam);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsCallback callback, nint lParam);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(nint windowHandle, out uint processId);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(nint windowHandle);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool PostMessage(nint windowHandle, uint message, nint wParam, nint lParam);

    private const uint WM_CLOSE = 0x0010;
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

    private sealed class StartingStore : IDisposable
    {
        public StartingStore(CancellationToken cancellationToken)
        {
            Cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        }

        public CancellationTokenSource Cancellation { get; }
        public TaskCompletionSource Completion { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public RunningStore? RunningRecord { get; set; }

        public void Dispose() => Cancellation.Dispose();
    }

    private sealed record RunningStore(
        string StoreId,
        Process Agent,
        Process Browser,
        FileStream LockHandle,
        string LockPath,
        string PipeName,
        string Capability,
        CancellationTokenSource IdentityCancellation,
        nint IconHandle)
    {
        private int _cleanupClaimed;

        public object LifecycleGate { get; } = new();
        public TaskCompletionSource CleanupCompletion { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool CleanupClaimed => Volatile.Read(ref _cleanupClaimed) != 0;

        public bool TryClaimCleanup() =>
            Interlocked.CompareExchange(ref _cleanupClaimed, 1, 0) == 0;
    }

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
