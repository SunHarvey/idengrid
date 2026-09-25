using System.Reflection;
using System.Text.Json;

namespace IdenGrid.Windows.Wpf;

internal static class ClientConfiguration
{
    private sealed record Settings(string ApiBaseUrl, bool BraveAdBlockOnlyMode = false);

    public static Uri LoadApiBaseAddress()
    {
        var settings = LoadSettings();
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

    public static bool LoadBraveAdBlockOnlyMode() => LoadSettings().BraveAdBlockOnlyMode;

    private static Settings LoadSettings()
    {
        using var stream = Assembly.GetExecutingAssembly()
            .GetManifestResourceStream("IdenGrid.ClientConfig.json")
            ?? throw new InvalidOperationException("客户端缺少服务器配置");
        return JsonSerializer.Deserialize<Settings>(stream, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        }) ?? throw new InvalidOperationException("客户端服务器配置无效");
    }
}
