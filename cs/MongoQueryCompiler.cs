using System.Text.RegularExpressions;
using MongoDB.Bson;
using MongoDB.Driver;
using QueryGateway.Config;
using QueryGateway.Models;

namespace QueryGateway.Services;

public sealed class MongoQueryCompiler
{
    private static readonly Regex SafeRegex = new(@"^[\p{L}\p{Nd}\s@\.\-_]+$", RegexOptions.Compiled);

    public (FilterDefinition<BsonDocument> Filter,
            SortDefinition<BsonDocument> Sort,
            ProjectionDefinition<BsonDocument> Projection,
            int Limit) Compile(QueryRequest req, CollectionRule rule, GlobalQueryOptions global)
    {
        var allowedFields = new HashSet<string>(rule.AllowedFields, StringComparer.OrdinalIgnoreCase);
        var allowedOps = new HashSet<string>(rule.AllowedOperators, StringComparer.OrdinalIgnoreCase);

        // Select / projection
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
        var sortSpecs = req.Sort;
        if (sortSpecs is null || sortSpecs.Count == 0)
        {
            sortSpecs = rule.DefaultSort?.Select(s => new SortSpec { Field = s.Field, Dir = s.Dir }).ToList()
                        ?? new List<SortSpec> { new() { Field = "_id", Dir = "desc" } };
        }

        foreach (var s in sortSpecs)
            EnsureAllowedField(s.Field, allowedFields);

        var sort = BuildSort(sortSpecs);

        // Filter
        int predicateCount = 0;
        var filter = req.Filter is null
            ? Builders<BsonDocument>.Filter.Empty
            : CompileFilterNode(req.Filter, allowedFields, allowedOps, global.MaxFilterDepth, ref predicateCount);

        if (predicateCount > global.MaxPredicates)
            throw new InvalidOperationException($"Too many predicates (max {global.MaxPredicates}).");

        return (filter, sort, projection, limit);
    }

    private static SortDefinition<BsonDocument> BuildSort(List<SortSpec> sorts)
    {
        var s = Builders<BsonDocument>.Sort;
        SortDefinition<BsonDocument>? built = null;

        foreach (var spec in sorts)
        {
            var dir = spec.Dir.Equals("desc", StringComparison.OrdinalIgnoreCase) ? s.Descending(spec.Field) : s.Ascending(spec.Field);
            built = built is null ? dir : built.Ascending("_id"); // placeholder (won't be used)
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
        int depth = 1)
    {
        if (depth > maxDepth)
            throw new InvalidOperationException($"Filter too deep (max depth {maxDepth}).");

        var f = Builders<BsonDocument>.Filter;

        switch (node)
        {
            case AndNode and:
                return f.And(and.Items.Select(x => CompileFilterNode(x, allowedFields, allowedOps, maxDepth, ref predicateCount, depth + 1)));
            case OrNode or:
                return f.Or(or.Items.Select(x => CompileFilterNode(x, allowedFields, allowedOps, maxDepth, ref predicateCount, depth + 1)));
            case PredicateNode p:
                predicateCount++;
                EnsureAllowedField(p.Field, allowedFields);
                EnsureAllowedOp(p.Op, allowedOps);
                return CompilePredicate(p);
            default:
                throw new InvalidOperationException("Unknown filter node.");
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

    private static FilterDefinition<BsonDocument> CompilePredicate(PredicateNode p)
    {
        var f = Builders<BsonDocument>.Filter;
        var op = p.Op.ToLowerInvariant();

        // Convert to BsonValue(s)
        BsonValue v = ToBsonValue(p.Value);

        return op switch
        {
            "eq"  => f.Eq(p.Field, v),
            "ne"  => f.Ne(p.Field, v),
            "gt"  => f.Gt(p.Field, v),
            "gte" => f.Gte(p.Field, v),
            "lt"  => f.Lt(p.Field, v),
            "lte" => f.Lte(p.Field, v),

            "in"  => f.In(p.Field, ToBsonArray(p.Value)),
            "nin" => f.Nin(p.Field, ToBsonArray(p.Value)),

            "contains"   => SafeRegexFilter(p.Field, p.Value, startsWith: false),
            "startswith" => SafeRegexFilter(p.Field, p.Value, startsWith: true),

            _ => throw new InvalidOperationException($"Unsupported operator '{p.Op}'.")
        };

        FilterDefinition<BsonDocument> SafeRegexFilter(string field, object? value, bool startsWith)
        {
            var s = value?.ToString() ?? "";
            if (s.Length == 0 || s.Length > 200)
                throw new InvalidOperationException("Text search value invalid.");

            // Reject “wild” input; keep it conservative to avoid expensive regex.
            if (!SafeRegex.IsMatch(s))
                throw new InvalidOperationException("Text search contains unsupported characters.");

            var escaped = Regex.Escape(s);
            var pattern = startsWith ? $"^{escaped}" : escaped;
            return f.Regex(field, new BsonRegularExpression(pattern, "i"));
        }
    }

    private static BsonArray ToBsonArray(object? value)
    {
        if (value is System.Text.Json.JsonElement je && je.ValueKind == System.Text.Json.JsonValueKind.Array)
        {
            var arr = new BsonArray();
            foreach (var item in je.EnumerateArray())
                arr.Add(ToBsonValue(item));
            return arr;
        }

        if (value is IEnumerable<object> list)
            return new BsonArray(list.Select(ToBsonValue));

        throw new InvalidOperationException("Value for 'in/nin' must be an array.");
    }

    private static BsonValue ToBsonValue(object? value)
    {
        if (value is null) return BsonNull.Value;

        if (value is System.Text.Json.JsonElement je)
        {
            return je.ValueKind switch
            {
                System.Text.Json.JsonValueKind.String => ToBsonFromString(je.GetString()!),
                System.Text.Json.JsonValueKind.Number => je.TryGetInt64(out var l) ? new BsonInt64(l) : new BsonDouble(je.GetDouble()),
                System.Text.Json.JsonValueKind.True => BsonBoolean.True,
                System.Text.Json.JsonValueKind.False => BsonBoolean.False,
                System.Text.Json.JsonValueKind.Null => BsonNull.Value,
                _ => throw new InvalidOperationException("Unsupported JSON value type in predicate.")
            };
        }

        // fallback
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
        if (MongoDB.Bson.ObjectId.TryParse(s, out var oid)) return oid;

        if (DateTimeOffset.TryParse(s, out var dto))
            return new BsonDateTime(dto.UtcDateTime);

        return new BsonString(s);
    }
}
