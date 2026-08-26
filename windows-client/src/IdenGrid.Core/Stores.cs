namespace IdenGrid.Core;

public static class StoreFilter
{
    public static IReadOnlyList<StoreDto> Apply(IEnumerable<StoreDto> stores, string query)
    {
        ArgumentNullException.ThrowIfNull(stores);
        query = (query ?? string.Empty).Trim();
        if (query.Length == 0) return stores.ToArray();
        return stores
            .Where(store =>
                store.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                store.NodeName.Contains(query, StringComparison.OrdinalIgnoreCase))
            .ToArray();
    }
}

public static class WindowsProfileLayout
{
    public static string UserDataDirectory(string applicationRoot, string storeId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationRoot);
        if (!ulong.TryParse(storeId, out var numericId) || numericId == 0 || numericId.ToString() != storeId)
        {
            throw new ArgumentException("storeId must be a canonical positive integer", nameof(storeId));
        }

        return Path.Combine(applicationRoot, "BrowserProfiles", $"store-{numericId}");
    }
}
