// Program.cs (single-file)
// .NET 9/10 Minimal API: MongoDB Read-only Query Gateway with
// ✅ JWT auth + scope-based authorization per collection (e.g., canReadBilling)
// ✅ Safe Query DSL (no raw Mongo query text)
// ✅ Cursor pagination (stable, no skip)
// ✅ Query cost scoring + hard limits
// ✅ Audit logging
// ✅ Correlation ID (X-Correlation-Id) end-to-end
// ✅ Rate limiting (per user or IP)
// ✅ OpenTelemetry metrics (+ optional tracing) + /metrics (Prometheus scrape)
// ✅ /schema endpoint (from allowlist rules)
// ✅ dryRun mode (compile/validate without hitting DB)
// ✅ Global kill switch
// ✅ OpenAPI + Scalar UI (dev only)
//
// Required packages:
//   dotnet add package MongoDB.Driver
//   dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
//   dotnet add package Microsoft.AspNetCore.OpenApi
//   dotnet add package Scalar.AspNetCore
//   dotnet add package OpenTelemetry.Extensions.Hosting
//   dotnet add package OpenTelemetry.Instrumentation.AspNetCore
//   dotnet add package OpenTelemetry.Exporter.Prometheus.AspNetCore
// Optional tracing exporter (OTLP):
//   dotnet add package OpenTelemetry.Exporter.OpenTelemetryProtocol

using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// -------------------- Options --------------------
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("Jwt"));
builder.Services.Configure<MongoOptions>(builder.Configuration.GetSection("Mongo"));
builder.Services.Configure<QueryGatewayOptions>(builder.Configuration.GetSection("QueryGateway"));

// -------------------- OpenAPI + Scalar --------------------
builder.Services.AddOpenApi();

// -------------------- Auth --------------------
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.Authority = builder.Configuration["Jwt:Authority"];
        o.Audience = builder.Configuration["Jwt:Audience"];
        o.RequireHttpsMetadata = true;
    });

builder.Services.AddAuthorization();

// -------------------- Rate Limiting --------------------
builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy("per-user-or-ip", ctx =>
    {
        var userKey =
            ctx.User?.Identity?.IsAuthenticated == true
                ? (ctx.User.FindFirst("sub")?.Value
                   ?? ctx.User.FindFirst("oid")?.Value
                   ?? ctx.User.Identity?.Name
                   ?? "auth-unknown")
                : (ctx.Connection.RemoteIpAddress?.ToString() ?? "ip-unknown");

        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: userKey,
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 120,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            });
    });
});

// -------------------- OpenTelemetry (Metrics + optional Tracing) --------------------
builder.Services.AddOpenTelemetry()
    .WithMetrics(m =>
    {
        m.AddAspNetCoreInstrumentation()
         .AddMeter(Otel.MeterName)
         .AddPrometheusExporter();
    })
    .WithTracing(t =>
    {
        // Optional tracing (works even without exporter; useful if you later add OTLP)
        t.AddAspNetCoreInstrumentation();

        // If you add OpenTelemetry.Exporter.OpenTelemetryProtocol and set OTEL_EXPORTER_OTLP_ENDPOINT,
        // uncomment the next line:
        // t.AddOtlpExporter();
    });

// -------------------- Services --------------------
builder.Services.AddSingleton<ICollectionRegistry, CollectionRegistry>();
builder.Services.AddSingleton<MongoQueryCompiler>();
builder.Services.AddSingleton<MongoQueryService>();

builder.Services.AddScoped<AuditContext>();

var app = builder.Build();

// -------------------- Pipeline --------------------
app.UseRateLimiter();

app.UseMiddleware<KillSwitchMiddleware>();      // global kill switch
app.UseMiddleware<CorrelationIdMiddleware>();   // sets X-Correlation-Id + logging scope

app.UseAuthentication();
app.UseAuthorization();

app.UseMiddleware<AuditLoggingMiddleware>();    // logs once per request (after auth)

// OpenAPI + Scalar UI: recommended to expose only in Development
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();            // /openapi/v1.json (default)
    app.MapScalarApiReference(); // Scalar UI
}

// Prometheus scrape endpoint for metrics
app.MapPrometheusScrapingEndpoint(); // /metrics

// -------------------- Endpoints --------------------
app.MapGet("/health", () => Results.Ok(new { status = "ok" }))
   .WithTags("System")
   .WithSummary("Health check");

// Optional: discovery endpoint (allow-listed collections)
app.MapGet("/v1/data/collections",
    (IOptions<QueryGatewayOptions> gw) =>
    {
        var result = gw.Value.Collections.Select(kvp => new
        {
            key = kvp.Key,
            collection = kvp.Value.CollectionName,
            requiredScopes = kvp.Value.RequiredScopes,
            allowedFields = kvp.Value.AllowedFields,
            allowedOperators = kvp.Value.AllowedOperators,
            maxLimit = kvp.Value.MaxLimit ?? gw.Value.Global.DefaultMaxLimit
        });

        return Results.Ok(result);
    })
   .RequireAuthorization()
   .RequireRateLimiting("per-user-or-ip")
   .WithTags("Query Gateway")
   .WithSummary("List allow-listed collections and query rules");

// /schema endpoint (from allowlist rules; optionally enhance with inferred types)
app.MapGet("/v1/data/{collectionKey}/schema",
    (string collectionKey, HttpContext http, ICollectionRegistry registry, IOptions<JwtOptions> jwt) =>
    {
        if (!registry.TryGetRule(collectionKey, out var rule))
            return Results.NotFound(new { error = "Unknown or not-allowed collection." });

        // Scope auth (same as query)
        if (rule.RequiredScopes is { Length: > 0 })
        {
            var scopeClaimType = jwt.Value.ScopeClaimType ?? "scope";
            if (!http.User.HasAnyScope(scopeClaimType, rule.RequiredScopes))
                return Results.Forbid();
        }

        return Results.Ok(new
        {
            collectionKey,
            collection = rule.CollectionName,
            requiredScopes = rule.RequiredScopes,
            fields = rule.AllowedFields.Select(f => new
            {
                name = f,
                // Optionally set types per field in config later; keep generic here.
                type = "unknown",
                filterable = true,
                sortable = true
            }),
            operators = rule.AllowedOperators,
            maxLimit = rule.MaxLimit
        });
    })
   .RequireAuthorization()
   .RequireRateLimiting("per-user-or-ip")
   .WithTags("Query Gateway")
   .WithSummary("Schema/metadata for a collection (based on allowlist rules)");

app.MapPost("/v1/data/{collectionKey}/query",
    async (
        string collectionKey,
        QueryRequest request,
        HttpContext http,
        AuditContext audit,
        IOptions<JwtOptions> jwt,
        ICollectionRegistry registry,
        MongoQueryService svc,
        CancellationToken ct) =>
    {
        audit.CollectionKey = collectionKey;

        if (!registry.TryGetRule(collectionKey, out var rule))
            return Results.NotFound(new { error = "Unknown or not-allowed collection." });

        audit.CollectionName = rule.CollectionName;
        audit.Limit = request.Page?.Limit;

        // Scope-based auth
        if (rule.RequiredScopes is { Length: > 0 })
        {
            var scopeClaimType = jwt.Value.ScopeClaimType ?? "scope";
            if (!http.User.HasAnyScope(scopeClaimType, rule.RequiredScopes))
                return Results.Forbid();
        }

        try
        {
            // dryRun: compile/validate/cost only, no DB call
            if (request.DryRun)
            {
                var compiled = svc.CompileOnly(rule, request, out var cost);
                audit.PredicateCount = compiled.PredicateCount;
                audit.Cost = cost.Score;

                Otel.QueriesTotal.Add(1, new KeyValuePair<string, object?>("collectionKey", collectionKey),
                                         new KeyValuePair<string, object?>("dryRun", true));
                Otel.QueryCost.Record(cost.Score, new KeyValuePair<string, object?>("collectionKey", collectionKey));

                return Results.Ok(new
                {
                    dryRun = true,
                    allowed = true,
                    collection = rule.CollectionName,
                    maxLimit = rule.MaxLimit,
                    cost = new { score = cost.Score, predicates = cost.Predicates, orNodes = cost.OrNodes, regexOps = cost.RegexOps },
                    compiled = new
                    {
                        limit = compiled.Limit,
                        // NOTE: we intentionally do NOT return raw Mongo query text or Bson in response
                        // to avoid “teaching” clients internals and to keep it safe.
                        cursorMode = "after(_id)"
                    }
                });
            }

            var sw = Stopwatch.StartNew();
            var result = await svc.QueryAsync(rule, request, ct);
            sw.Stop();

            audit.Returned = result.Returned;
            audit.PredicateCount = result.PredicateCount;
            audit.Cost = result.CostScore;

            // Metrics
            Otel.QueriesTotal.Add(1, new KeyValuePair<string, object?>("collectionKey", collectionKey),
                                     new KeyValuePair<string, object?>("dryRun", false));
            Otel.QueryDurationMs.Record(sw.Elapsed.TotalMilliseconds,
                new KeyValuePair<string, object?>("collectionKey", collectionKey));
            Otel.QueryReturned.Record(result.Returned,
                new KeyValuePair<string, object?>("collectionKey", collectionKey));
            Otel.QueryCost.Record(result.CostScore,
                new KeyValuePair<string, object?>("collectionKey", collectionKey));

            return Results.Ok(new
            {
                items = result.Items,
                pageInfo = new
                {
                    returned = result.Returned,
                    limit = result.Limit,
                    nextCursor = result.NextCursor
                }
            });
        }
        catch (Exception ex)
        {
            // In production: keep response generic; log full exception in server logs
            return Results.BadRequest(new { error = ex.Message });
        }
    })
   .RequireAuthorization()
   .RequireRateLimiting("per-user-or-ip")
   .WithTags("Query Gateway")
   .WithSummary("Query an allow-listed MongoDB collection")
   .WithDescription("Safe DSL filter/sort/select with cursor pagination, cost scoring, audit logs, and metrics.")
   .Produces(StatusCodes.Status200OK)
   .Produces(StatusCodes.Status400BadRequest)
   .Produces(StatusCodes.Status401Unauthorized)
   .Produces(StatusCodes.Status403Forbidden)
   .Produces(StatusCodes.Status404NotFound);

app.Run();


// ============================================================================
// OpenTelemetry custom meters
// ============================================================================
static class Otel
{
    public const string MeterName = "QueryGateway";
    public static readonly Meter Meter = new(MeterName);

    public static readonly Counter<long> QueriesTotal =
        Meter.CreateCounter<long>("queries_total", unit: "{query}", description: "Total queries (including dryRun)");

    public static readonly Histogram<double> QueryDurationMs =
        Meter.CreateHistogram<double>("query_duration_ms", unit: "ms", description: "Mongo query duration (ms)");

    public static readonly Histogram<long> QueryReturned =
        Meter.CreateHistogram<long>("query_returned", unit: "{documents}", description: "Returned document count");

    public static readonly Histogram<int> QueryCost =
        Meter.CreateHistogram<int>("query_cost", unit: "{score}", description: "Estimated query cost score");
}


// ============================================================================
// Options / Config Models
// ============================================================================
sealed class JwtOptions
{
    public string? Authority { get; set; }
    public string? Audience { get; set; }
    public string? ScopeClaimType { get; set; } = "scope";
}

sealed class MongoOptions
{
    public string ConnectionString { get; set; } = default!;
    public string Database { get; set; } = default!;
    public int MaxQueryMilliseconds { get; set; } = 2000;
}

sealed class QueryGatewayOptions
{
    public bool Enabled { get; set; } = true;
    public GlobalQueryOptions Global { get; set; } = new();
    public Dictionary<string, CollectionRule> Collections { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

sealed class GlobalQueryOptions
{
    public int DefaultMaxLimit { get; set; } = 200;
    public int MaxFilterDepth { get; set; } = 6;
    public int MaxPredicates { get; set; } = 50;

    // Cost scoring guardrail
    public int MaxQueryCost { get; set; } = 50;
}

sealed class CollectionRule
{
    public string CollectionName { get; set; } = default!;
    public string[] RequiredScopes { get; set; } = Array.Empty<string>();

    public string[] AllowedFields { get; set; } = Array.Empty<string>();
    public string[] AllowedOperators { get; set; } = Array.Empty<string>();

    public int? MaxLimit { get; set; }
    public SortRule[]? DefaultSort { get; set; }
}

sealed class SortRule
{
    public string Field { get; set; } = default!;
    public string Dir { get; set; } = "asc";
}


// ============================================================================
// Query DSL
// ============================================================================
sealed class QueryRequest
{
    public FilterNode? Filter { get; init; }
    public List<SortSpec>? Sort { get; init; }
    public List<string>? Select { get; init; }
    public PageSpec? Page { get; init; }
    public bool DryRun { get; init; } = false;
}

sealed class PageSpec
{
    public int? Limit { get; init; }
    public string? After { get; init; } // cursor (base64 json)
}

sealed class SortSpec
{
    public string Field { get; init; } = default!;
    public string Dir { get; init; } = "asc"; // asc|desc
}

[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(AndNode), "and")]
[JsonDerivedType(typeof(OrNode), "or")]
[JsonDerivedType(typeof(PredicateNode), "pred")]
abstract class FilterNode { }

sealed class AndNode : FilterNode
{
    public List<FilterNode> Items { get; init; } = new();
}

sealed class OrNode : FilterNode
{
    public List<FilterNode> Items { get; init; } = new();
}

sealed class PredicateNode : FilterNode
{
    public string Field { get; init; } = default!;
    public string Op { get; init; } = default!; // eq, in, gte, contains, ...
    public object? Value { get; init; }
}


// ============================================================================
// Scope helpers (your flags like canReadBilling, canReadMetadata)
// ============================================================================
static class ScopeExtensions
{
    // Supports:
    // - "scope": "canReadBilling canReadMetadata" (space separated)
    // - multiple "scope" claims
    // - "scp" claim
    public static bool HasAnyScope(this ClaimsPrincipal user, string scopeClaimType, IEnumerable<string> required)
    {
        var req = required?.ToArray() ?? Array.Empty<string>();
        if (req.Length == 0) return true;

        var scopes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var claimType in new[] { scopeClaimType, "scope", "scp" }.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            foreach (var c in user.FindAll(claimType))
            {
                var parts = c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                foreach (var p in parts) scopes.Add(p);
            }
        }

        return req.Any(scopes.Contains);
    }
}


// ============================================================================
// Middlewares: Kill switch, CorrelationId, Audit logging
// ============================================================================
sealed class KillSwitchMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IOptionsMonitor<QueryGatewayOptions> _opts;

    public KillSwitchMiddleware(RequestDelegate next, IOptionsMonitor<QueryGatewayOptions> opts)
    {
        _next = next;
        _opts = opts;
    }

    public async Task Invoke(HttpContext ctx)
    {
        if (!_opts.CurrentValue.Enabled &&
            ctx.Request.Path.StartsWithSegments("/v1/data", StringComparison.OrdinalIgnoreCase))
        {
            ctx.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            await ctx.Response.WriteAsJsonAsync(new { error = "Query gateway disabled" });
            return;
        }

        await _next(ctx);
    }
}

sealed class CorrelationIdMiddleware
{
    public const string HeaderName = "X-Correlation-Id";
    private readonly RequestDelegate _next;

    public CorrelationIdMiddleware(RequestDelegate next) => _next = next;

    public async Task Invoke(HttpContext ctx, ILogger<CorrelationIdMiddleware> logger)
    {
        var id = ctx.Request.Headers[HeaderName].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(id))
            id = Guid.NewGuid().ToString("N");

        ctx.Items[HeaderName] = id;
        ctx.Response.Headers[HeaderName] = id;

        using (logger.BeginScope(new Dictionary<string, object?>
        {
            ["CorrelationId"] = id
        }))
        {
            await _next(ctx);
        }
    }
}

sealed class AuditContext
{
    public string? CollectionKey { get; set; }
    public string? CollectionName { get; set; }
    public int? Returned { get; set; }
    public int? Limit { get; set; }
    public int? PredicateCount { get; set; }
    public int? Cost { get; set; }
}

sealed class AuditLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<AuditLoggingMiddleware> _logger;

    public AuditLoggingMiddleware(RequestDelegate next, ILogger<AuditLoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task Invoke(HttpContext ctx, AuditContext audit)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            await _next(ctx);
        }
        finally
        {
            sw.Stop();

            var sub = ctx.User.FindFirst("sub")?.Value ?? ctx.User.FindFirst("oid")?.Value;
            var scope = ctx.User.FindFirst("scope")?.Value ?? ctx.User.FindFirst("scp")?.Value;
            var corr = ctx.Items.TryGetValue(CorrelationIdMiddleware.HeaderName, out var v) ? v?.ToString() : null;

            _logger.LogInformation(
                "AUDIT corr={Corr} method={Method} path={Path} status={Status} ms={Ms} sub={Sub} scopes={Scopes} colKey={ColKey} col={Col} returned={Returned} limit={Limit} preds={Preds} cost={Cost}",
                corr,
                ctx.Request.Method,
                ctx.Request.Path.Value,
                ctx.Response.StatusCode,
                sw.ElapsedMilliseconds,
                sub,
                scope,
                audit.CollectionKey,
                audit.CollectionName,
                audit.Returned,
                audit.Limit,
                audit.PredicateCount,
                audit.Cost);
        }
    }
}


// ============================================================================
// Registry (allow-listed collections)
// ============================================================================
interface ICollectionRegistry
{
    bool TryGetRule(string key, out CollectionRule rule);
}

sealed class CollectionRegistry : ICollectionRegistry
{
    private readonly QueryGatewayOptions _opts;
    public CollectionRegistry(IOptions<QueryGatewayOptions> opts) => _opts = opts.Value;

    public bool TryGetRule(string key, out CollectionRule rule)
        => _opts.Collections.TryGetValue(key, out rule!);
}


// ============================================================================
// Query cost model
// ============================================================================
sealed class QueryCost
{
    public int Predicates { get; set; }
    public int OrNodes { get; set; }
    public int RegexOps { get; set; }

    public int Score => Predicates + (OrNodes * 2) + (RegexOps * 5);
}


// ============================================================================
// Mongo query compilation + execution (safe DSL + cursor pagination)
// ============================================================================
sealed class MongoQueryCompiler
{
    public CompiledQuery Compile(QueryRequest req, CollectionRule rule, GlobalQueryOptions global, out QueryCost cost)
    {
        cost = new QueryCost();

        var allowedFields = new HashSet<string>(rule.AllowedFields, StringComparer.OrdinalIgnoreCase);
        var allowedOps = new HashSet<string>(rule.AllowedOperators, StringComparer.OrdinalIgnoreCase);

        // Projection
        var select = (req.Select is { Count: > 0 } ? req.Select : rule.AllowedFields.ToList())
            .Where(f => allowedFields.Contains(f))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (select.Count == 0)
            throw new InvalidOperationException("No selectable fields allowed for this collection.");

        var projection = Builders<BsonDocument>.Projection.Include(select[0]);
        foreach (var f in select.Skip(1))
            projection = projection.Include(f);

        // Limit
        var max = rule.MaxLimit ?? global.DefaultMaxLimit;
        var limit = req.Page?.Limit ?? Math.Min(50, max);
        if (limit <= 0 || limit > max)
            throw new InvalidOperationException($"Limit must be between 1 and {max}.");

        // Sort
        // Cursor pagination assumes a stable sort; we enforce final tie-breaker on _id.
        var sortSpecs = req.Sort;
        if (sortSpecs is null || sortSpecs.Count == 0)
        {
            sortSpecs = rule.DefaultSort?.Select(s => new SortSpec { Field = s.Field, Dir = s.Dir }).ToList()
                        ?? new List<SortSpec> { new() { Field = "_id", Dir = "desc" } };
        }

        foreach (var s in sortSpecs)
            EnsureAllowedField(s.Field, allowedFields);

        // Always include _id as last sort key if not present
        if (!sortSpecs.Any(s => s.Field.Equals("_id", StringComparison.OrdinalIgnoreCase)))
            sortSpecs.Add(new SortSpec { Field = "_id", Dir = "asc" });

        var sort = BuildSort(sortSpecs);

        // Filter
        int predicateCount = 0;
        var filter = req.Filter is null
            ? Builders<BsonDocument>.Filter.Empty
            : CompileFilterNode(req.Filter, allowedFields, allowedOps, global.MaxFilterDepth, ref predicateCount, cost);

        if (predicateCount > global.MaxPredicates)
            throw new InvalidOperationException($"Too many predicates (max {global.MaxPredicates}).");

        // Cursor pagination: After cursor (by _id)
        ObjectId? afterId = null;
        if (!string.IsNullOrWhiteSpace(req.Page?.After))
        {
            afterId = Cursor.Decode(req.Page.After);
            filter = Builders<BsonDocument>.Filter.And(filter, Builders<BsonDocument>.Filter.Gt("_id", afterId.Value));
        }

        // Cost guardrail
        if (cost.Score > global.MaxQueryCost)
            throw new InvalidOperationException($"Query cost {cost.Score} exceeds limit {global.MaxQueryCost}.");

        return new CompiledQuery(filter, sort, projection, limit, predicateCount, afterId);
    }

    private static SortDefinition<BsonDocument> BuildSort(List<SortSpec> sorts)
    {
        var s = Builders<BsonDocument>.Sort;
        SortDefinition<BsonDocument>? built = null;

        foreach (var spec in sorts)
        {
            var dir = spec.Dir.Equals("desc", StringComparison.OrdinalIgnoreCase)
                ? s.Descending(spec.Field)
                : s.Ascending(spec.Field);

            built = built is null ? dir : Builders<BsonDocument>.Sort.Combine(built, dir);
        }

        return built ?? s.Descending("_id");
    }

    private static FilterDefinition<BsonDocument> CompileFilterNode(
        FilterNode node,
        HashSet<string> allowedFields,
        HashSet<string> allowedOps,
        int maxDepth,
        ref int predicateCount,
        QueryCost cost,
        int depth = 1)
    {
        if (depth > maxDepth)
            throw new InvalidOperationException($"Filter too deep (max depth {maxDepth}).");

        var f = Builders<BsonDocument>.Filter;

        switch (node)
        {
            case AndNode and:
                return f.And(and.Items.Select(x => CompileFilterNode(x, allowedFields, allowedOps, maxDepth, ref predicateCount, cost, depth + 1)));

            case OrNode or:
                cost.OrNodes++;
                return f.Or(or.Items.Select(x => CompileFilterNode(x, allowedFields, allowedOps, maxDepth, ref predicateCount, cost, depth + 1)));

            case PredicateNode p:
                return CompilePredicate(p, allowedFields, allowedOps, ref predicateCount, cost);

            default:
                throw new InvalidOperationException("Unknown filter node.");
        }
    }

    private static FilterDefinition<BsonDocument> CompilePredicate(
        PredicateNode p,
        HashSet<string> allowedFields,
        HashSet<string> allowedOps,
        ref int predicateCount,
        QueryCost cost)
    {
        predicateCount++;
        cost.Predicates++;

        EnsureAllowedField(p.Field, allowedFields);
        EnsureAllowedOp(p.Op, allowedOps);

        var f = Builders<BsonDocument>.Filter;
        var op = p.Op.ToLowerInvariant();

        return op switch
        {
            "eq" => f.Eq(p.Field, ToBsonValue(p.Value)),
            "ne" => f.Ne(p.Field, ToBsonValue(p.Value)),
            "gt" => f.Gt(p.Field, ToBsonValue(p.Value)),
            "gte" => f.Gte(p.Field, ToBsonValue(p.Value)),
            "lt" => f.Lt(p.Field, ToBsonValue(p.Value)),
            "lte" => f.Lte(p.Field, ToBsonValue(p.Value)),
            "in" => f.In(p.Field, ToBsonArray(p.Value)),
            "nin" => f.Nin(p.Field, ToBsonArray(p.Value)),

            "contains" => SafeRegex(p.Field, p.Value, startsWith: false, cost),
            "startswith" => SafeRegex(p.Field, p.Value, startsWith: true, cost),

            _ => throw new InvalidOperationException($"Unsupported operator '{p.Op}'.")
        };

        static FilterDefinition<BsonDocument> SafeRegex(string field, object? value, bool startsWith, QueryCost cost)
        {
            cost.RegexOps++;

            var s = value?.ToString() ?? "";
            if (s.Length == 0 || s.Length > 200)
                throw new InvalidOperationException("Text search value invalid.");

            // Escape user input: safe-ish regex (still bounded by length)
            var escaped = System.Text.RegularExpressions.Regex.Escape(s);
            var pattern = startsWith ? $"^{escaped}" : escaped;

            return Builders<BsonDocument>.Filter.Regex(field, new BsonRegularExpression(pattern, "i"));
        }
    }

    private static void EnsureAllowedField(string field, HashSet<string> allowed)
    {
        if (!allowed.Contains(field))
            throw new InvalidOperationException($"Field '{field}' is not allowed.");
    }

    private static void EnsureAllowedOp(string op, HashSet<string> allowedOps)
    {
        if (!allowedOps.Contains(op))
            throw new InvalidOperationException($"Operator '{op}' is not allowed.");
    }

    private static BsonArray ToBsonArray(object? value)
    {
        if (value is JsonElement je && je.ValueKind == JsonValueKind.Array)
        {
            var arr = new BsonArray();
            foreach (var item in je.EnumerateArray())
                arr.Add(ToBsonValue(item));
            return arr;
        }

        throw new InvalidOperationException("Value for 'in/nin' must be an array.");
    }

    private static BsonValue ToBsonValue(object? value)
    {
        if (value is null) return BsonNull.Value;

        if (value is JsonElement je)
        {
            return je.ValueKind switch
            {
                JsonValueKind.String => ToBsonFromString(je.GetString()!),
                JsonValueKind.Number => je.TryGetInt64(out var l) ? new BsonInt64(l) : new BsonDouble(je.GetDouble()),
                JsonValueKind.True => BsonBoolean.True,
                JsonValueKind.False => BsonBoolean.False,
                JsonValueKind.Null => BsonNull.Value,
                _ => throw new InvalidOperationException("Unsupported JSON value type in predicate.")
            };
        }

        if (value is string s) return ToBsonFromString(s);
        if (value is int i) return new BsonInt32(i);
        if (value is long l2) return new BsonInt64(l2);
        if (value is double d) return new BsonDouble(d);
        if (value is bool b) return new BsonBoolean(b);
        if (value is DateTime dt) return new BsonDateTime(dt);

        return BsonValue.Create(value);
    }

    private static BsonValue ToBsonFromString(string s)
    {
        if (ObjectId.TryParse(s, out var oid)) return oid;

        if (DateTimeOffset.TryParse(s, out var dto))
            return new BsonDateTime(dto.UtcDateTime);

        return new BsonString(s);
    }
}

readonly record struct CompiledQuery(
    FilterDefinition<BsonDocument> Filter,
    SortDefinition<BsonDocument> Sort,
    ProjectionDefinition<BsonDocument> Projection,
    int Limit,
    int PredicateCount,
    ObjectId? AfterId);

static class Cursor
{
    // cursor = base64( {"id":"<objectId>"} )
    public static string Encode(ObjectId id)
        => Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new { id = id.ToString() }));

    public static ObjectId Decode(string cursor)
    {
        var bytes = Convert.FromBase64String(cursor);
        var el = JsonSerializer.Deserialize<JsonElement>(bytes);
        var id = el.GetProperty("id").GetString();
        return ObjectId.Parse(id);
    }
}

sealed class MongoQueryService
{
    private readonly IMongoDatabase _db;
    private readonly MongoOptions _mongo;
    private readonly QueryGatewayOptions _gw;
    private readonly MongoQueryCompiler _compiler;

    public MongoQueryService(IOptions<MongoOptions> mongo, IOptions<QueryGatewayOptions> gw, MongoQueryCompiler compiler)
    {
        _mongo = mongo.Value;
        _gw = gw.Value;
        _compiler = compiler;

        var client = new MongoClient(_mongo.ConnectionString);
        _db = client.GetDatabase(_mongo.Database);
    }

    public CompiledQuery CompileOnly(CollectionRule rule, QueryRequest request, out QueryCost cost)
        => _compiler.Compile(request, rule, _gw.Global, out cost);

    public async Task<QueryResult> QueryAsync(CollectionRule rule, QueryRequest request, CancellationToken ct)
    {
        var collection = _db.GetCollection<BsonDocument>(rule.CollectionName);

        var compiled = _compiler.Compile(request, rule, _gw.Global, out var cost);

        var options = new FindOptions<BsonDocument>
        {
            Projection = compiled.Projection,
            Sort = compiled.Sort,
            Limit = compiled.Limit,
            MaxTime = TimeSpan.FromMilliseconds(_mongo.MaxQueryMilliseconds)
        };

        using var cursor = await collection.FindAsync(compiled.Filter, options, ct);
        var docs = await cursor.ToListAsync(ct);

        var items = docs.Select(d => JsonDocument.Parse(d.ToJson()).RootElement).ToList();

        // next cursor = last _id returned
        string? nextCursor = null;
        if (docs.Count > 0 && docs[^1].TryGetValue("_id", out var lastIdVal) && lastIdVal.IsObjectId)
            nextCursor = Cursor.Encode(lastIdVal.AsObjectId);

        return new QueryResult(items, items.Count, compiled.Limit, compiled.PredicateCount, cost.Score, nextCursor);
    }
}

readonly record struct QueryResult(
    List<JsonElement> Items,
    int Returned,
    int Limit,
    int PredicateCount,
    int CostScore,
    string? NextCursor);
