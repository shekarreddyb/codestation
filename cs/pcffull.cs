using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

#pragma warning disable CS1998

// ----------------------------
// Models you provide as input
// ----------------------------
public sealed record AppStopItem(
    string FoundationUrl,
    string SpaceName,
    string AppId,     // might be empty; we’ll try name if ID fails
    string AppName    // used if ID lookup fails
);

// ----------------------------
// Result models for logging
// ----------------------------
public enum StopOutcome
{
    StoppedById,
    StoppedByNameLookup,
    NotFoundTreatedAsSuccess,
    AlreadyStopped,
    Failed
}

public sealed record StopResult(AppStopItem Item, StopOutcome Outcome, string Message);

// ----------------------------
// Minimal config for endpoints
// Adjust these to your PCF/API environment
// ----------------------------
public static class ApiConfig
{
    // Token: e.g., UAA/OAuth endpoint or your gateway auth
    public static string TokenEndpoint(string foundationBase) =>
        $"{foundationBase.TrimEnd('/')}/oauth/token";

    // Stop by ID (Cloud Foundry v3 semantics are often POST /v3/apps/{guid}/actions/stop)
    public static string StopAppById(string foundationBase, string appId) =>
        $"{foundationBase.TrimEnd('/')}/v3/apps/{appId}/actions/stop";

    // Find app by name in space (adjust to your API;
    // in CF v3 you’d typically need the space GUID and call /v3/apps?names=...&space_guids=...
    // If you only have SpaceName, ensure your gateway supports name-based lookup or map name->GUID elsewhere)
    public static string FindAppByName(string foundationBase, string spaceName, string appName) =>
        $"{foundationBase.TrimEnd('/')}/v3/apps:search?spaceName={Uri.EscapeDataString(spaceName)}&name={Uri.EscapeDataString(appName)}";

    // Deserialize your search response accordingly
}

// ----------------------------
// Token provider with per-foundation caching
// ----------------------------
public sealed class TokenProvider
{
    private readonly ConcurrentDictionary<string, (string token, DateTimeOffset expires)> _cache = new();

    // Plug your client credentials / grant type here
    private readonly string _clientId;
    private readonly string _clientSecret;
    private readonly HttpClient _http;

    public TokenProvider(string clientId, string clientSecret, HttpClient http)
    {
        _clientId = clientId;
        _clientSecret = clientSecret;
        _http = http;
    }

    public async Task<string> GetTokenAsync(string foundation, CancellationToken ct)
    {
        if (_cache.TryGetValue(foundation, out var entry) && entry.expires > DateTimeOffset.UtcNow.AddMinutes(1))
            return entry.token;

        var tokenResp = await RequestTokenAsync(foundation, ct);
        // Assume OAuth2 style: {"access_token":"...","expires_in":3600}
        using var doc = JsonDocument.Parse(tokenResp);
        var token = doc.RootElement.GetProperty("access_token").GetString()!;
        var expiresIn = doc.RootElement.TryGetProperty("expires_in", out var exp)
            ? TimeSpan.FromSeconds(exp.GetInt32()) : TimeSpan.FromMinutes(30);

        _cache[foundation] = (token, DateTimeOffset.UtcNow.Add(expiresIn));
        return token;
    }

    private async Task<string> RequestTokenAsync(string foundation, CancellationToken ct)
    {
        var url = ApiConfig.TokenEndpoint(foundation);
        var body = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = _clientId,
            ["client_secret"] = _clientSecret]
        );

        using var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = body };
        var resp = await _http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
        return await resp.Content.ReadAsStringAsync(ct);
    }
}

// ----------------------------
// Platform client: stop by ID, find by name
// ----------------------------
public sealed class PlatformClient
{
    private readonly HttpClient _http;

    public PlatformClient(HttpClient http) => _http = http;

    public void SetBearer(string token) => _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

    // Simple resilient send with retry/backoff for 429/5xx
    private async Task<HttpResponseMessage> SendWithRetryAsync(Func<HttpRequestMessage> requestFactory, CancellationToken ct)
    {
        const int maxAttempts = 5;
        int attempt = 0;

        while (true)
        {
            attempt++;
            using var req = requestFactory();
            var resp = await _http.SendAsync(req, ct);

            if ((int)resp.StatusCode == 429 || ((int)resp.StatusCode >= 500 && (int)resp.StatusCode <= 599))
            {
                if (attempt >= maxAttempts) return resp;
                var delay = TimeSpan.FromMilliseconds(200 * Math.Pow(2, attempt - 1));
                await Task.Delay(delay, ct);
                continue;
            }

            return resp;
        }
    }

    public async Task<(bool success, bool alreadyStopped, string? message)> StopByIdAsync(string foundation, string appId, CancellationToken ct)
    {
        var url = ApiConfig.StopAppById(foundation, appId);

        var resp = await SendWithRetryAsync(
            () => new HttpRequestMessage(HttpMethod.Post, url),
            ct
        );

        if (resp.StatusCode == HttpStatusCode.NotFound)
            return (false, false, "App not found by id");

        if (resp.IsSuccessStatusCode)
        {
            // Optionally check body to decide if already stopped; here we assume success
            return (true, false, "Stopped by id");
        }

        var txt = await resp.Content.ReadAsStringAsync(ct);
        return (false, false, $"Failed stop by id ({(int)resp.StatusCode}): {txt}");
    }

    public async Task<string?> FindLatestIdByNameAsync(string foundation, string spaceName, string appName, CancellationToken ct)
    {
        var url = ApiConfig.FindAppByName(foundation, spaceName, appName);
        var resp = await SendWithRetryAsync(() => new HttpRequestMessage(HttpMethod.Get, url), ct);

        if (resp.StatusCode == HttpStatusCode.NotFound)
            return null;

        if (!resp.IsSuccessStatusCode)
            return null;

        // Example response shape; adjust to your API
        // {
        //   "apps":[ {"id":"guid1","updated_at":"2025-09-14T10:00:00Z"}, ... ]
        // }
        var json = await resp.Content.ReadAsStringAsync(ct);
        using var doc = JsonDocument.Parse(json);

        if (!doc.RootElement.TryGetProperty("apps", out var apps) || apps.ValueKind != JsonValueKind.Array || apps.GetArrayLength() == 0)
            return null;

        // Pick latest by updated_at
        var latest = apps.EnumerateArray()
            .Select(a => new
            {
                id = a.TryGetProperty("id", out var idEl) ? idEl.GetString() : null,
                updated = a.TryGetProperty("updated_at", out var uEl) && uEl.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(uEl.GetString(), out var dt)
                    ? dt : (DateTimeOffset?)null
            })
            .Where(x => !string.IsNullOrWhiteSpace(x.id))
            .OrderByDescending(x => x.updated ?? DateTimeOffset.MinValue)
            .FirstOrDefault();

        return latest?.id;
    }
}

// ----------------------------
// Status updater – replace with your DB/API calls
// ----------------------------
public static class StatusUpdater
{
    public static async Task UpdateAsync(AppStopItem item, StopOutcome outcome, string message, CancellationToken ct)
    {
        // TODO: Push to your API/DB; this is a placeholder
        await Task.Yield();
        Console.WriteLine($"[STATUS] {item.FoundationUrl} | {item.SpaceName} | {(item.AppId ?? "-")} | {item.AppName} => {outcome} ({message})");
    }
}

// ----------------------------
// Orchestrator
// ----------------------------
public sealed class StopperOrchestrator
{
    private readonly TokenProvider _tokens;
    private readonly Func<HttpClient> _httpFactory;
    private readonly int _maxParallelPerFoundation;

    public StopperOrchestrator(TokenProvider tokens, Func<HttpClient> httpFactory, int maxParallelPerFoundation = 8)
    {
        _tokens = tokens;
        _httpFactory = httpFactory;
        _maxParallelPerFoundation = Math.Max(1, maxParallelPerFoundation);
    }

    public async Task<IReadOnlyCollection<StopResult>> RunAsync(IEnumerable<AppStopItem> items, CancellationToken ct)
    {
        var results = new ConcurrentBag<StopResult>();

        // Group by foundation; process each foundation sequentially or in parallel as you prefer.
        // Here we process foundations sequentially to avoid cross-foundation token storms,
        // but do parallel inside each foundation.
        var byFoundation = items.GroupBy(i => i.FoundationUrl);

        foreach (var foundationGroup in byFoundation)
        {
            string foundation = foundationGroup.Key;
            Console.WriteLine($"\n=== Processing foundation: {foundation} ===");

            // 1) Fetch token once per foundation
            string token = await _tokens.GetTokenAsync(foundation, ct);

            // 2) Create a client bound to this foundation
            using var http = _httpFactory();
            http.BaseAddress = new Uri(foundation);
            var platform = new PlatformClient(http);
            platform.SetBearer(token);

            // 3) Parallelize stops within this foundation
            var throttler = new SemaphoreSlim(_maxParallelPerFoundation);
            var tasks = foundationGroup.Select(async item =>
            {
                await throttler.WaitAsync(ct);
                try
                {
                    var res = await HandleOneAsync(platform, item, ct);
                    results.Add(res);
                    await StatusUpdater.UpdateAsync(item, res.Outcome, res.Message, ct);
                }
                finally
                {
                    throttler.Release();
                }
            }).ToList();

            await Task.WhenAll(tasks);
        }

        return results.ToArray();
    }

    private async Task<StopResult> HandleOneAsync(PlatformClient platform, AppStopItem item, CancellationToken ct)
    {
        // Try by ID if present
        if (!string.IsNullOrWhiteSpace(item.AppId))
        {
            var (success, alreadyStopped, message) = await platform.StopByIdAsync(item.FoundationUrl, item.AppId, ct);
            if (success)
                return new(item, alreadyStopped ? StopOutcome.AlreadyStopped : StopOutcome.StoppedById, message ?? "Stopped by id");

            if (!message?.Contains("not found", StringComparison.OrdinalIgnoreCase) ?? false)
                return new(item, StopOutcome.Failed, message ?? "Failed stop by id");
        }

        // Lookup by name if ID not provided or not found
        var latestId = await platform.FindLatestIdByNameAsync(item.FoundationUrl, item.SpaceName, item.AppName, ct);
        if (!string.IsNullOrWhiteSpace(latestId))
        {
            var (success2, alreadyStopped2, msg2) = await platform.StopByIdAsync(item.FoundationUrl, latestId!, ct);
            if (success2)
                return new(item, alreadyStopped2 ? StopOutcome.AlreadyStopped : StopOutcome.StoppedByNameLookup, msg2 ?? "Stopped by name lookup");
            // If failed here (e.g., transient), surface failure
            return new(item, StopOutcome.Failed, msg2 ?? "Failed after name lookup");
        }

        // Treat not found as success
        return new(item, StopOutcome.NotFoundTreatedAsSuccess, "App not found; treated as successfully stopped");
    }
}

// ----------------------------
// Program entry
// ----------------------------
public class Program
{
    public static async Task Main()
    {
        var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        // EXAMPLE INPUT – replace with your real list
        var items = new List<AppStopItem>
        {
            new("https://foundation-a.example", "space-one",  "app-guid-1", "orders-api"),
            new("https://foundation-a.example", "space-one",  "",           "inventory-ui"),
            new("https://foundation-b.example", "space-prod", "app-guid-9", "payments-api"),
            new("https://foundation-b.example", "space-prod", "",           "orchestrator")
        };

        // Shared HTTP for token provider
        var sharedHttp = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(60)
        };

        var tokenProvider = new TokenProvider(
            clientId:    Environment.GetEnvironmentVariable("PCF_CLIENT_ID")     ?? "your-client-id",
            clientSecret:Environment.GetEnvironmentVariable("PCF_CLIENT_SECRET") ?? "your-secret",
            http: sharedHttp
        );

        // Per-request HttpClient factory (can be IHttpClientFactory in DI instead)
        Func<HttpClient> httpFactory = () => new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(60)
        };

        var orchestrator = new StopperOrchestrator(tokenProvider, httpFactory, maxParallelPerFoundation: 8);
        var results = await orchestrator.RunAsync(items, cts.Token);

        // ----------------------------
        // Final summary
        // ----------------------------
        var grouped = results.GroupBy(r => r.Item.FoundationUrl)
            .OrderBy(g => g.Key);

        Console.WriteLine("\n========== SUMMARY ==========");
        foreach (var g in grouped)
        {
            Console.WriteLine($"\nFoundation: {g.Key}");
            var counts = g.GroupBy(x => x.Outcome).ToDictionary(x => x.Key, x => x.Count());
            int ok = counts.GetValueOrDefault(StopOutcome.StoppedById) +
                     counts.GetValueOrDefault(StopOutcome.StoppedByNameLookup) +
                     counts.GetValueOrDefault(StopOutcome.NotFoundTreatedAsSuccess) +
                     counts.GetValueOrDefault(StopOutcome.AlreadyStopped);

            int failed = counts.GetValueOrDefault(StopOutcome.Failed);

            Console.WriteLine($"  Success (incl. already stopped & not-found-treated-success): {ok}");
            Console.WriteLine($"  Failed: {failed}");

            foreach (var res in g.OrderBy(r => r.Item.SpaceName).ThenBy(r => r.Item.AppName))
            {
                Console.WriteLine($"    [{res.Outcome}] {res.Item.SpaceName} | {res.Item.AppName} | id={res.Item.AppId ?? "-"} -> {res.Message}");
            }
        }

        Console.WriteLine("\nAll done.");
    }
}