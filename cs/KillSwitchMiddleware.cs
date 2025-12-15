sealed class KillSwitchMiddleware
{
    private readonly RequestDelegate _next;
    private readonly QueryGatewayOptions _opts;

    public KillSwitchMiddleware(RequestDelegate next, IOptions<QueryGatewayOptions> opts)
    {
        _next = next;
        _opts = opts.Value;
    }

    public async Task Invoke(HttpContext ctx)
    {
        if (!_opts.Enabled)
        {
            ctx.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            await ctx.Response.WriteAsJsonAsync(new { error = "Query gateway disabled" });
            return;
        }

        await _next(ctx);
    }
}
