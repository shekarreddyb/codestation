using Microsoft.Extensions.Options;
using QueryGateway.Config;

namespace QueryGateway.Services;

public interface ICollectionRegistry
{
    bool TryGetRule(string key, out CollectionRule rule);
}

public sealed class CollectionRegistry : ICollectionRegistry
{
    private readonly QueryGatewayOptions _opts;
    public CollectionRegistry(IOptions<QueryGatewayOptions> opts) => _opts = opts.Value;

    public bool TryGetRule(string key, out CollectionRule rule)
        => _opts.Collections.TryGetValue(key, out rule!);
}
