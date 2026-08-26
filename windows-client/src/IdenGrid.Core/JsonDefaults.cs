using System.Text.Json;

namespace IdenGrid.Core;

public static class JsonDefaults
{
    public static JsonSerializerOptions Options { get; } = new()
    {
        PropertyNameCaseInsensitive = false,
    };
}
