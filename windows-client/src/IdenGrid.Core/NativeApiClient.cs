using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace IdenGrid.Core;

public sealed class ApiException(int statusCode) : Exception($"Server rejected request with HTTP {statusCode}")
{
    public int StatusCode { get; } = statusCode;
}

public sealed class NativeApiClient
{
    private readonly HttpClient _http;

    public NativeApiClient(HttpClient http)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        if (_http.BaseAddress is null) throw new ArgumentException("HttpClient BaseAddress is required", nameof(http));
    }

    public Task<SessionDto> LoginAsync(
        string username,
        string password,
        string deviceId,
        string deviceName,
        CancellationToken cancellationToken = default) =>
        SendAsync<SessionDto>(
            HttpMethod.Post,
            "api/native/login",
            new LoginRequest(username, password, deviceId, deviceName, "windows"),
            authorization: null,
            cancellationToken);

    public Task<SessionDto> RefreshAsync(
        string refreshToken,
        CancellationToken cancellationToken = default) =>
        SendAsync<SessionDto>(
            HttpMethod.Post,
            "api/native/refresh",
            body: null,
            authorization: new AuthenticationHeaderValue("Refresh", refreshToken),
            cancellationToken);

    public Task LogoutAsync(
        string accessToken,
        CancellationToken cancellationToken = default) =>
        SendWithoutResponseAsync(
            HttpMethod.Post,
            "api/native/logout",
            new AuthenticationHeaderValue("Bearer", accessToken),
            cancellationToken);

    public async Task<IReadOnlyList<StoreDto>> GetStoresAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var result = await SendAsync<StoreListDto>(
            HttpMethod.Get,
            "api/native/stores",
            body: null,
            authorization: new AuthenticationHeaderValue("Bearer", accessToken),
            cancellationToken).ConfigureAwait(false);
        return result.Stores;
    }

    private async Task<T> SendAsync<T>(
        HttpMethod method,
        string relativePath,
        object? body,
        AuthenticationHeaderValue? authorization,
        CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(method, relativePath)
        {
            Headers = { Accept = { new MediaTypeWithQualityHeaderValue("application/json") } },
        };
        request.Headers.Authorization = authorization;
        if (body is not null) request.Content = JsonContent.Create(body, options: JsonDefaults.Options);

        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) throw new ApiException((int)response.StatusCode);
        var value = await response.Content.ReadFromJsonAsync<T>(JsonDefaults.Options, cancellationToken)
            .ConfigureAwait(false);
        return value ?? throw new ApiException((int)response.StatusCode);
    }

    private async Task SendWithoutResponseAsync(
        HttpMethod method,
        string relativePath,
        AuthenticationHeaderValue authorization,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, relativePath);
        request.Headers.Authorization = authorization;
        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) throw new ApiException((int)response.StatusCode);
    }

    private sealed record LoginRequest(
        [property: JsonPropertyName("username")] string Username,
        [property: JsonPropertyName("password")] string Password,
        [property: JsonPropertyName("device_id")] string DeviceId,
        [property: JsonPropertyName("device_name")] string DeviceName,
        [property: JsonPropertyName("platform")] string Platform);
}
