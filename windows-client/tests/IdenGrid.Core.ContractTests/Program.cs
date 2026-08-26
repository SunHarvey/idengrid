using System.Text.Json;
using IdenGrid.Core;

static void Require(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException($"FAIL: {message}");
}

var sessionJson = """
{
  "access_token":"access-token-for-contract",
  "refresh_token":"session.secret-for-contract",
  "device_session_id":"device-session-1",
  "access_expires_at":"2026-08-21T12:15:00+00:00",
  "refresh_expires_at":"2026-09-21T12:00:00+00:00"
}
""";
var session = JsonSerializer.Deserialize<SessionDto>(sessionJson, JsonDefaults.Options)!;
Require(session.AccessToken == "access-token-for-contract", "session access token DTO");
Require(session.DeviceSessionId == "device-session-1", "device session DTO");

Require(LoginPresentation.FailureMessage(401) == "用户名或者密码错误", "401 login message");
Require(LoginPresentation.FailureMessage(403) == "用户名或者密码错误", "403 login message");
Require(LoginPresentation.FailureMessage(500) == "登录失败，请稍后重试", "generic login message");

var now = DateTimeOffset.Parse("2026-08-21T12:00:00+00:00");
var expiry = now.AddMinutes(15);
Require(AccessTokenRefreshSchedule.Delay(expiry, now) == TimeSpan.FromMinutes(13), "two minute refresh margin");
Require(AccessTokenRefreshSchedule.Delay(now.AddSeconds(30), now) == TimeSpan.FromSeconds(5), "minimum refresh delay");
Require(AccessTokenRefreshSchedule.RetryDelay(0) == TimeSpan.FromSeconds(30), "initial retry");
Require(AccessTokenRefreshSchedule.RetryDelay(9) == TimeSpan.FromMinutes(5), "retry cap");

var stores = new[]
{
    new StoreDto("2", "新加坡01", "新加坡节点", "online", true, "198.51.100.20", 0, 10),
    new StoreDto("3", "香港01", "香港节点", "online", true, "203.0.113.30", 0, 10),
};
Require(StoreFilter.Apply(stores, "香港").Single().Id == "3", "store search by name/node");
Require(StoreFilter.Apply(stores, "").Count == 2, "empty search returns all");

var root = @"C:\Users\test\AppData\Local\IdenGrid";
var store2 = WindowsProfileLayout.UserDataDirectory(root, "2");
var store3 = WindowsProfileLayout.UserDataDirectory(root, "3");
Require(Path.GetFileName(store2) == "store-2", "store-2 unique user-data-dir basename");
Require(Path.GetFileName(store3) == "store-3", "store-3 unique user-data-dir basename");
Require(store2 != store3, "profiles remain isolated");
Require(!store2.EndsWith(Path.DirectorySeparatorChar + "Profile", StringComparison.OrdinalIgnoreCase), "avoid colliding Profile basename");

var requests = new List<HttpRequestMessage>();
var responses = new Queue<HttpResponseMessage>(new[]
{
    new HttpResponseMessage(System.Net.HttpStatusCode.OK)
    {
        Content = new StringContent(sessionJson),
    },
    new HttpResponseMessage(System.Net.HttpStatusCode.OK)
    {
        Content = new StringContent("{\"stores\":[]}"),
    },
    new HttpResponseMessage(System.Net.HttpStatusCode.OK)
    {
        Content = new StringContent(sessionJson),
    },
    new HttpResponseMessage(System.Net.HttpStatusCode.OK)
    {
        Content = new StringContent("{\"ok\":true}"),
    },
    new HttpResponseMessage(System.Net.HttpStatusCode.Unauthorized)
    {
        Content = new StringContent("{\"detail\":\"Invalid credentials\"}"),
    },
});
using var http = new HttpClient(new RecordingHandler(requests, responses))
{
    BaseAddress = new Uri("https://api.example.com/"),
};
var api = new NativeApiClient(http);
var loggedIn = await api.LoginAsync("member", "password", "device-1", "Windows PC");
Require(loggedIn.DeviceSessionId == "device-session-1", "native login response");
Require(requests[0].RequestUri?.AbsolutePath == "/api/native/login", "native login path");
var loginBody = await requests[0].Content!.ReadAsStringAsync();
Require(loginBody.Contains("\"device_id\":\"device-1\"", StringComparison.Ordinal), "login device id body");
Require(!loginBody.Contains("native_access_token", StringComparison.Ordinal), "login body has no internal token field");

var listed = await api.GetStoresAsync("access-token-for-contract");
Require(listed.Count == 0, "native stores response");
Require(requests[1].RequestUri?.AbsolutePath == "/api/native/stores", "native stores path");
Require(requests[1].Headers.Authorization?.Scheme == "Bearer", "native stores bearer scheme");

var refreshed = await api.RefreshAsync("refresh-token-for-contract");
Require(refreshed.AccessToken == "access-token-for-contract", "native refresh response");
Require(requests[2].RequestUri?.AbsolutePath == "/api/native/refresh", "native refresh path");
Require(requests[2].Headers.Authorization?.Scheme == "Refresh", "native refresh scheme");
Require(requests[2].Headers.Authorization?.Parameter == "refresh-token-for-contract", "native refresh token header");

await api.LogoutAsync("access-token-for-contract");
Require(requests[3].RequestUri?.AbsolutePath == "/api/native/logout", "native logout path");
Require(requests[3].Headers.Authorization?.Scheme == "Bearer", "native logout bearer");

try
{
    _ = await api.LoginAsync("member", "wrong", "device-1", "Windows PC");
    throw new InvalidOperationException("FAIL: unauthorized login must throw");
}
catch (ApiException error)
{
    Require(error.StatusCode == 401, "unauthorized status retained without exposing body");
}

Console.WriteLine("IdenGrid Windows core contract tests passed: 33");

file sealed class RecordingHandler(
    List<HttpRequestMessage> requests,
    Queue<HttpResponseMessage> responses) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        requests.Add(request);
        return Task.FromResult(responses.Dequeue());
    }
}
