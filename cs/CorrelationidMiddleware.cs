sealed class CorrelationIdMiddleware
{
    public const string Header = "X-Correlation-Id";
    private readonly RequestDelegate _next;

    public CorrelationIdMiddleware(RequestDelegate next) => _next = next;

    public async Task Invoke(HttpContext ctx)
    {
        var id = ctx.Request.Headers[Header].FirstOrDefault()
                 ?? Guid.NewGuid().ToString("N");

        ctx.Items[Header] = id;
        ctx.Response.Headers[Header] = id;

        using (Serilog.Context.LogContext.PushProperty("CorrelationId", id))
        {
            await _next(ctx);
        }
    }
}
