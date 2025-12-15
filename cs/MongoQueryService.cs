using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;
using QueryGateway.Config;
using QueryGateway.Models;

namespace QueryGateway.Services;

public sealed class MongoOptions
{
    public string ConnectionString { get; set; } = default!;
    public string Database { get; set; } = default!;
    public int MaxQueryMilliseconds { get; set; } = 2000;
}

public sealed class MongoQueryService
{
    private readonly IMongoDatabase _db;
    private readonly MongoOptions _mongo;
    private readonly QueryGatewayOptions _gw;
    private readonly MongoQueryCompiler _compiler;

    public MongoQueryService(
        IOptions<MongoOptions> mongo,
        IOptions<QueryGatewayOptions> gw,
        MongoQueryCompiler compiler)
    {
        _mongo = mongo.Value;
        _gw = gw.Value;
        _compiler = compiler;

        var client = new MongoClient(_mongo.ConnectionString);
        _db = client.GetDatabase(_mongo.Database);
    }

    public async Task<(List<BsonDocument> Items, int Returned)> QueryAsync(
        string collectionName,
        CollectionRule rule,
        QueryRequest request,
        CancellationToken ct)
    {
        var coll = _db.GetCollection<BsonDocument>(collectionName);

        var (filter, sort, projection, limit) = _compiler.Compile(request, rule, _gw.Global);

        var options = new FindOptions<BsonDocument>
        {
            Projection = projection,
            Sort = sort,
            Limit = limit,
            MaxTime = TimeSpan.FromMilliseconds(_mongo.MaxQueryMilliseconds)
        };

        using var cursor = await coll.FindAsync(filter, options, ct);
        var items = await cursor.ToListAsync(ct);

        return (items, items.Count);
    }
}
