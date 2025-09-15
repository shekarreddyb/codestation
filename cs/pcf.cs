public sealed class TokenProvider
{
    private readonly ConcurrentDictionary<string, (string token, DateTimeOffset expires)> _cache = new();
    private readonly HttpClient _http;

    private readonly string _prodClientId;
    private readonly string _prodClientSecret;
    private readonly string _nonProdClientId;
    private readonly string _nonProdClientSecret;

    public TokenProvider(HttpClient http,
        string prodClientId, string prodClientSecret,
        string nonProdClientId, string nonProdClientSecret)
    {
        _http = http;
        _prodClientId = prodClientId;
        _prodClientSecret = prodClientSecret;
        _nonProdClientId = nonProdClientId;
        _nonProdClientSecret = nonProdClientSecret;
    }

    public async Task<string> GetTokenAsync(string foundationUrl, CancellationToken ct)
    {
        if (_cache.TryGetValue(foundationUrl, out var entry) && entry.expires > DateTimeOffset.UtcNow.AddMinutes(1))
            return entry.token;

        // Decide account based on foundation
        var (clientId, clientSecret) = IsProd(foundationUrl)
            ? (_prodClientId, _prodClientSecret)
            : (_nonProdClientId, _nonProdClientSecret);

        var tokenResp = await RequestTokenAsync(foundationUrl, clientId, clientSecret, ct);

        using var doc = JsonDocument.Parse(tokenResp);
        var token = doc.RootElement.GetProperty("access_token").GetString()!;
        var expiresIn = doc.RootElement.TryGetProperty("expires_in", out var exp)
            ? TimeSpan.FromSeconds(exp.GetInt32())
            : TimeSpan.FromMinutes(30);

        _cache[foundationUrl] = (token, DateTimeOffset.UtcNow.Add(expiresIn));
        return token;
    }

    private async Task<string> RequestTokenAsync(string foundation, string clientId, string clientSecret, CancellationToken ct)
    {
        var url = ApiConfig.TokenEndpoint(foundation);
        var body = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret
        });

        using var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = body };
        var resp = await _http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
        return await resp.Content.ReadAsStringAsync(ct);
    }

    private static bool IsProd(string foundationUrl)
    {
        // Rule for prod detection
        // Examples: contains "prod", or exact host match
        return foundationUrl.Contains("prod", StringComparison.OrdinalIgnoreCase);
    }
}

var tokenProvider = new TokenProvider(
    sharedHttp,
    prodClientId:    Environment.GetEnvironmentVariable("PCF_PROD_CLIENT_ID")    ?? "prod-client-id",
    prodClientSecret:Environment.GetEnvironmentVariable("PCF_PROD_CLIENT_SECRET")?? "prod-secret",
    nonProdClientId: Environment.GetEnvironmentVariable("PCF_NONPROD_CLIENT_ID") ?? "nonprod-client-id",
    nonProdClientSecret:Environment.GetEnvironmentVariable("PCF_NONPROD_CLIENT_SECRET") ?? "nonprod-secret"
);
