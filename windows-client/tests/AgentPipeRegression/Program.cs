using System.Diagnostics;
using System.IO.Pipes;
using System.Reflection;
using System.Text;
using IdenGrid.Windows.Wpf;

if (args is ["hold"])
{
    await Task.Delay(Timeout.InfiniteTimeSpan);
    return;
}
if (args is ["exit"]) return;

static Process StartFixtureProcess(string mode)
{
    var executable = Environment.ProcessPath ?? throw new Exception("Missing .NET host path");
    var start = new ProcessStartInfo(executable) { UseShellExecute = false };
    if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
        start.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
    start.ArgumentList.Add(mode);
    return Process.Start(start) ?? throw new Exception("Could not start harmless fixture process");
}

var scenario = args.Length == 0 ? "partial" : args[0];
var pipeName = "ig-" + Guid.NewGuid().ToString("N")[..12];
using var server = scenario == "no-server" ? null : new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
using var stop = new CancellationTokenSource();
var serverTask = server is null ? Task.CompletedTask : Task.Run(async () =>
{
    await server.WaitForConnectionAsync(stop.Token);
    if (scenario == "write-stall")
    {
        await Task.Delay(Timeout.InfiniteTimeSpan, stop.Token);
        return;
    }
    var buffer = new byte[4096];
    var count = await server.ReadAsync(buffer, stop.Token);
    if (count == 0) throw new Exception("Request was not written");
    if (scenario is "success" or "eof")
    {
        await server.WriteAsync(Encoding.UTF8.GetBytes("{\"status\":\"connected\",\"socks_host\":\"127.0.0.1\",\"socks_port\":9000,\"store_id\":1,\"device_id\":\"fixture\"}" + (scenario == "success" ? "\n" : "")));
        await server.FlushAsync();
        if (scenario == "eof") { server.Dispose(); return; }
    }
    else if (scenario == "partial")
    {
        await server.WriteAsync(Encoding.UTF8.GetBytes("{\"status\":\"connected\""));
        await server.FlushAsync();
    }
    await Task.Delay(Timeout.InfiniteTimeSpan, stop.Token);
});

try
{
    if (scenario is "close" or "cleanup-error" or "cleanup-primary")
    {
        var store = typeof(WindowsStoreProcessManager).GetNestedType("RunningStore", BindingFlags.NonPublic)!;
        var manager = new WindowsStoreProcessManager(new Uri("https://example.invalid"), "fixture");
        using var agent = StartFixtureProcess("hold");
        using var browser = StartFixtureProcess("exit");
        await browser.WaitForExitAsync();
        var leasePath = Path.Combine(Path.GetTempPath(), $"idengrid-lease-{Guid.NewGuid():N}");
        var lockPath = scenario is "cleanup-error" or "cleanup-primary" ? leasePath + "-blocked" : leasePath;
        var lease = new FileStream(leasePath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        if (scenario is "cleanup-error" or "cleanup-primary") Directory.CreateDirectory(lockPath);
        var identity = new CancellationTokenSource();
        try
        {
            var record = Activator.CreateInstance(store, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance,
                null, ["1", agent, browser, lease, lockPath, pipeName, "fixture-capability", identity, (nint)0], null)!;
            var running = typeof(WindowsStoreProcessManager).GetField("_running", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(manager)!;
            if (!(bool)running.GetType().GetMethod("TryAdd")!.Invoke(running, ["1", record])!)
                throw new Exception("Could not set up running store");
            if (scenario == "cleanup-primary") browser.Dispose(); // Forces StopBrowserAsync to fail before lease cleanup.
            var close = manager.CloseAsync("1");
            if (scenario is "cleanup-error" or "cleanup-primary")
            {
                Exception? cleanupFailure = null;
                try { await close.WaitAsync(TimeSpan.FromSeconds(9)); }
                catch (Exception error) { cleanupFailure = error; }
                var correctError = scenario == "cleanup-primary"
                    ? cleanupFailure is AggregateException aggregate
                        && aggregate.InnerExceptions.Count == 2
                        && aggregate.InnerExceptions[0] is InvalidOperationException
                        && aggregate.InnerExceptions[1] is UnauthorizedAccessException
                    : cleanupFailure is IOException or UnauthorizedAccessException;
                if (!correctError
                    || !agent.HasExited || manager.State("1") != StoreRuntimeState.Failed
                    || manager.IsRunning("1") || !Directory.Exists(lockPath) || !lease.SafeFileHandle.IsClosed)
                    throw new Exception("Lease deletion failure or primary stop error was lost during failed-state cleanup", cleanupFailure);
                var completionSource = store.GetProperty("CleanupCompletion")!.GetValue(record)!;
                var completion = (Task)completionSource.GetType().GetProperty("Task")!.GetValue(completionSource)!;
                Exception? waiterError = null;
                try { await completion.WaitAsync(TimeSpan.FromSeconds(2)); }
                catch (Exception error) { waiterError = error; }
                if (waiterError is not UnauthorizedAccessException)
                    throw new Exception("Concurrent cleanup waiter did not receive lease deletion failure", waiterError);
                await manager.CloseAsync("1").WaitAsync(TimeSpan.FromSeconds(2));
                if (manager.State("1") != StoreRuntimeState.Failed)
                    throw new Exception("Second close falsely changed failed lease cleanup to Idle");
                Console.WriteLine($"PASS {scenario}: Agent terminated; {cleanupFailure!.GetType().Name} reported; state Failed");
            }
            else
            {
                await close.WaitAsync(TimeSpan.FromSeconds(9));
                if (!agent.HasExited || File.Exists(lockPath) || manager.IsRunning("1") || manager.State("1") != StoreRuntimeState.Idle)
                    throw new Exception("Shutdown did not kill Agent, release lease, or clean running record");
                Console.WriteLine("PASS close: timed-out shutdown continued Agent termination, lease release and cleanup");
            }
        }
        finally
        {
            if (!agent.HasExited) agent.Kill(true);
            lease.Dispose();
            File.Delete(leasePath);
            if (scenario is "cleanup-error" or "cleanup-primary") Directory.Delete(lockPath);
            identity.Dispose();
        }
        return;
    }
    var method = typeof(WindowsStoreProcessManager).GetMethod(
        scenario is "shutdown" or "eof" or "write-stall" ? "RequestAsync" : "WaitForStatusAsync", BindingFlags.Static | BindingFlags.NonPublic)!;
    using var caller = new CancellationTokenSource();
    if (scenario == "cancel") caller.CancelAfter(120);
    var stopwatch = Stopwatch.StartNew();
    var parameters = scenario is "shutdown" or "eof" or "write-stall"
        ? new object?[] { pipeName, "fixture-capability", "shutdown", caller.Token, scenario == "write-stall" ? new string('x', 8 * 1024 * 1024) : null }
        : [pipeName, "fixture-capability", TimeSpan.FromMilliseconds(400), caller.Token];
    var task = (Task)method.Invoke(null, parameters)!;
    Exception? failure = null;
    try { await task.WaitAsync(TimeSpan.FromSeconds(2)); }
    catch (Exception error) { failure = error; }
    stopwatch.Stop();
    if (scenario == "success")
    {
        if (failure != null) throw new Exception("Complete status response failed", failure);
    }
    else if (scenario == "cancel")
    {
        if (failure is not OperationCanceledException || !caller.IsCancellationRequested)
            throw new Exception("Caller cancellation was not propagated", failure);
    }
    else if (scenario == "eof")
    {
        if (failure is not IOException) throw new Exception("Response without LF was accepted", failure);
    }
    else
    {
        if (failure is not TimeoutException || !task.IsCompleted)
            throw new Exception($"IPC exceeded its total budget ({stopwatch.ElapsedMilliseconds}ms)", failure);
        if (stopwatch.Elapsed > (scenario is "shutdown" or "write-stall" ? TimeSpan.FromSeconds(3) : TimeSpan.FromMilliseconds(900)))
            throw new Exception($"IPC timeout occurred too late ({stopwatch.ElapsedMilliseconds}ms)");
    }
    Console.WriteLine($"PASS {scenario}: {stopwatch.ElapsedMilliseconds}ms, {failure?.GetType().Name ?? "response"}");
}
finally
{
    stop.Cancel();
    server?.Dispose();
    try { await serverTask.WaitAsync(TimeSpan.FromSeconds(2)); }
    catch (OperationCanceledException) { }
    catch (IOException) { }
}

namespace IdenGrid.Windows.Wpf
{
    internal static class StoreTaskbarIcon
    {
        public static string LabelFor(string name, string id) => name;
        public static string ColorFor(string id) => "#000000";
        public static string Create(string root, string name, string id) => "fixture.ico";
    }
}
