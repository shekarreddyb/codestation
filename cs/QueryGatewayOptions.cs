namespace QueryGateway.Config;

public sealed class QueryGatewayOptions
{
    public GlobalQueryOptions Global { get; set; } = new();
    public Dictionary<string, CollectionRule> Collections { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class GlobalQueryOptions
{
    public int DefaultMaxLimit { get; set; } = 200;
    public int MaxFilterDepth { get; set; } = 6;
    public int MaxPredicates { get; set; } = 50;
}

public sealed class CollectionRule
{
    public string CollectionName { get; set; } = default!;
    public string[] RequiredScopes { get; set; } = Array.Empty<string>();

    public string[] AllowedFields { get; set; } = Array.Empty<string>();
    public string[] AllowedOperators { get; set; } = Array.Empty<string>();

    public int? MaxLimit { get; set; }
    public SortRule[]? DefaultSort { get; set; }
}

public sealed class SortRule
{
    public string Field { get; set; } = default!;
    public string Dir { get; set; } = "asc";
}
