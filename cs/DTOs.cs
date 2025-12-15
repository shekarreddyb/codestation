using System.Text.Json.Serialization;

namespace QueryGateway.Models;

public sealed class QueryRequest
{
    public FilterNode? Filter { get; init; }
    public List<SortSpec>? Sort { get; init; }
    public List<string>? Select { get; init; }
    public PageSpec? Page { get; init; }
}

public sealed class PageSpec
{
    public int? Limit { get; init; }
    public string? Cursor { get; init; } // optional: for future cursor paging
}

public sealed class SortSpec
{
    public string Field { get; init; } = default!;
    public string Dir { get; init; } = "asc"; // asc|desc
}

[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(AndNode), "and")]
[JsonDerivedType(typeof(OrNode), "or")]
[JsonDerivedType(typeof(PredicateNode), "pred")]
public abstract class FilterNode { }

public sealed class AndNode : FilterNode
{
    public List<FilterNode> Items { get; init; } = new();
}

public sealed class OrNode : FilterNode
{
    public List<FilterNode> Items { get; init; } = new();
}

public sealed class PredicateNode : FilterNode
{
    public string Field { get; init; } = default!;
    public string Op { get; init; } = default!;     // eq, gt, contains, ...
    public object? Value { get; init; }
}
