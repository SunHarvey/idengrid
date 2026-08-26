using System.Reflection;
using System.Text.Json;

namespace IdenGrid.Windows.Wpf;

internal static class ClientConfiguration
{
    private sealed record Settings(string ApiBaseUrl);

    public static Uri LoadApiBaseAddress()
    {
        using var stream = Assembly.GetExecutingAssembly()
            .GetManifestResourceStream("IdenGrid.ClientConfig.json")
            ?? throw new InvalidOperationException("客户端缺少服务器配置");
        var settings = JsonSerializer.Deserialize<Settings>(stream, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        }) ?? throw new InvalidOperationException("客户端服务器配置无效");
        var uri = new Uri(settings.ApiBaseUrl, UriKind.Absolute);
        if (uri.Scheme != Uri.UriSchemeHttps
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidOperationException("客户端服务器配置必须是HTTPS Origin");
        }
        return uri;
    }
}
