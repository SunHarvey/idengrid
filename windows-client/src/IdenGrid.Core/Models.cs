using System.Text.Json.Serialization;

namespace IdenGrid.Core;

public sealed record SessionDto(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("refresh_token")] string RefreshToken,
    [property: JsonPropertyName("device_session_id")] string DeviceSessionId,
    [property: JsonPropertyName("access_expires_at")] DateTimeOffset AccessExpiresAt,
    [property: JsonPropertyName("refresh_expires_at")] DateTimeOffset RefreshExpiresAt);

public sealed record StoreDto(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("node_name")] string NodeName,
    [property: JsonPropertyName("health_status")] string HealthStatus,
    [property: JsonPropertyName("enabled")] bool Enabled,
    [property: JsonPropertyName("expected_public_ipv4")] string? ExpectedPublicIpv4,
    [property: JsonPropertyName("active_connections")] int ActiveConnections,
    [property: JsonPropertyName("max_connections")] int MaxConnections,
    [property: JsonPropertyName("status")] string Status = "available",
    [property: JsonPropertyName("maintenance_mode")] bool MaintenanceMode = false,
    [property: JsonPropertyName("actual_public_ipv4")] string? ActualPublicIpv4 = null,
    [property: JsonPropertyName("latency_ms")] double? LatencyMs = null,
    [property: JsonPropertyName("legacy_profile_path")] string? LegacyProfilePath = null);

public sealed record StoreListDto(
    [property: JsonPropertyName("stores")] IReadOnlyList<StoreDto> Stores);
