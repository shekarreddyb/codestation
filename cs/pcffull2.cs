using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

// ----------------------------
// Models you provide as input
// ----------------------------
public sealed class AppStopItem
{
    public string FoundationUrl { get; private set; }
    public string SpaceName     { get; private set; }
    public string AppId         { get; private set; } // may be empty
    public string AppName       { get; private set; }

    public AppStopItem(string foundationUrl, string spaceName, string appId, string appName)
    {
        FoundationUrl = foundationUrl ?? "";
        SpaceName     = spaceName ?? "";
        AppId         = appId ?? "";
        AppName       = appName ?? "";
    }
}

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

public sealed class StopResult
{
    public AppStopItem Item { get; private set; }
    public StopOutcome Outcome { get; private set; }
    public string Message { get; private set; }

    public StopResult(AppStopItem item, StopOutcome outcome, string message)
    {
        Item = item;
        Outcome = outcome;
        Message = message ?? "";
    }
}

// ----------------------------
// Minimal config for endpoints
// Adjust these to your PCF/API environment
// ----------------------------
public static class ApiConfig
{
    public static string TokenEndpoint(string foundationBase)
    {
        return foundationBase.TrimEnd('/') + "/oauth/token";
    }

    // Stop by ID (CF v3: POST /v3/apps/{guid}/actions/stop)
    public static string StopAppById(string foundationBase, string appId)
    {
        return foundationBase.TrimEnd('/') + "/v3/apps/" + appId + "/actions/stop";
    }

    // Find app by name in space (adjust for your gateway)
    public static string FindAppByName(string foundationBase, string spaceName, string appName)
    {
        return foundationBase.TrimEnd('/') + "/v3/apps:search?spaceName=" +
               Uri.EscapeDataString(spaceName) + "&name=" + Uri.EscapeDataString(appName);
    }
}

// ----------------------------
// Token provider with prod/non-prod branching
// ----------------------------
public sealed class TokenCacheEntry
{
    public string Token { get; set; }
    public DateTimeOffset Expires { get; set; }

    public TokenCacheEntry(string token, DateTimeOffset expires)
    {
        Token = token;
        Expires = expires;
    }
}

public sealed class TokenProvider
{
    private readonly ConcurrentDictionary<string, TokenCacheEntry> _cache =
        new ConcurrentDictionary<string, TokenCacheEntry>();

    private readonly HttpClient _http;

    private readonly string _prodClientId;
    private readonly string _prodClientSecret;
    private readonly string _nonProdClientId;
    private readonly string _nonProdClientSecret;

    public TokenProvider(
        HttpClient http,
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
        TokenCacheEntry entry;
        if (_cache.TryGetValue(foundationUrl, out entry))
        {
            if (entry.Expires > DateTimeOffset.UtcNow.AddMinutes(1))
                return entry.Token;
        }

        var creds = IsProd(foundationUrl)
            ? new ClientCreds(_prodClientId, _prodClientSecret)
            : new ClientCreds(_nonProdClientId, _nonProdClientSecret);

        var tokenResp = await RequestTokenAsync(foundationUrl, creds.ClientId, creds.ClientSecret, ct).ConfigureAwait(false);

        using (var doc = JsonDocument.Parse(tokenResp))
        {
            var root = doc.RootElement;
            var token = root.GetProperty("access_token").GetString();
            var expiresIn = TimeSpan.FromMinutes(30);
            JsonElement expEl;
            if (root.TryGetProperty("expires_in", out expEl))
            {
                try { expiresIn = TimeSpan.FromSeconds(expEl.GetInt32()); }
                catch { /* keep default */ }
            }

            var cached = new TokenCacheEntry(token ?? "", DateTimeOffset.UtcNow.Add(expiresIn));
            _cache[foundationUrl] = cached;
            return cached.Token;
        }
    }

    private async Task<string> RequestTokenAsync(string foundation, string clientId, string clientSecret, CancellationToken ct)
    {
        var url = ApiConfig.TokenEndpoint(foundation);
        var dict = new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" },
            { "client_id", clientId },
            { "client_secret", clientSecret }
        };
        using (var body = new FormUrlEncodedContent(dict))
        using (var req = new HttpRequestMessage(HttpMethod.Post, url))
        {
            req.Content = body;
            using (var resp = await _http.SendAsync(req, ct).ConfigureAwait(false))
            {
                resp.EnsureSuccessStatusCode();
                // Older frameworks don’t have ReadAsStringAsync(ct)
                return await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            }
        }
    }

    private static bool IsProd(string foundationUrl)
    {
        // Replace with your exact rule set (domain match/regex/etc)
        return foundationUrl != null &&
               foundationUrl.IndexOf("prod", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private sealed class ClientCreds
    {
        public string ClientId { get; private set; }
        public string ClientSecret { get; private set; }
        public ClientCreds(string id, string secret) { ClientId = id; ClientSecret = secret; }
    }
}

// ----------------------------
// Platform client: stop by ID, find by name
// ----------------------------
public sealed class StopByIdResult
{
    public bool Success { get; private set; }
    public bool AlreadyStopped { get; private set; }
    public string Message { get; private set; }

    public StopByIdResult(bool success, bool alreadyStopped, string message)
    {
        Success = success;
        AlreadyStopped = alreadyStopped;
        Message = message ?? "";
    }
}

public sealed class PlatformClient
{
    private readonly HttpClient _http;

    public PlatformClient(HttpClient http)
    {
        _http = http;
    }

    public void SetBearer(string token)
    {
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token ?? "");
    }

    private async Task<HttpResponseMessage> SendWithRetryAsync(Func<HttpRequestMessage> requestFactory, CancellationToken ct)
    {
        const int maxAttempts = 5;
        int attempt = 0;

        while (true)
        {
            attempt++;
            using (var req = requestFactory())
            {
                var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);

                int code = (int)resp.StatusCode;
                if (code == 429 || (code >= 500 && code <= 599))
                {
                    if (attempt >= maxAttempts)
                        return resp;

                    var delayMs = (int)(200 * Math.Pow(2, attempt - 1));
                    await Task.Delay(TimeSpan.FromMilliseconds(delayMs), ct).ConfigureAwait(false);
                    // retry loop
                    continue;
                }

                return resp; // success or non-retriable
            }
        }
    }

    public async Task<StopByIdResult> StopByIdAsync(string foundation, string appId, CancellationToken ct)
    {
        var url = ApiConfig.StopAppById(foundation, appId);

        using (var resp = await SendWithRetryAsync(
            () => new HttpRequestMessage(HttpMethod.Post, url), ct).ConfigureAwait(false))
        {
            if (resp.StatusCode == HttpStatusCode.NotFound)
                return new StopByIdResult(false, false, "App not found by id");

            if (resp.IsSuccessStatusCode)
            {
                // Optionally inspect body to detect "already stopped"
                return new StopByIdResult(true, false, "Stopped by id");
            }

            var txt = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            return new StopByIdResult(false, false, "Failed stop by id (" + (int)resp.StatusCode + "): " + txt);
        }
    }

    public async Task<string> FindLatestIdByNameAsync(string foundation, string spaceName, string appName, CancellationToken ct)
    {
        var url = ApiConfig.FindAppByName(foundation, spaceName, appName);
        using (var resp = await SendWithRetryAsync(() => new HttpRequestMessage(HttpMethod.Get, url), ct).ConfigureAwait(false))
        {
            if (resp.StatusCode == HttpStatusCode.NotFound)
                return null;

            if (!resp.IsSuccessStatusCode)
                return null;

            var json = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            using (var doc = JsonDocument.Parse(json))
            {
                JsonElement apps;
                var root = doc.RootElement;
                if (!root.TryGetProperty("apps", out apps) ||
                    apps.ValueKind != JsonValueKind.Array ||
                    apps.GetArrayLength() == 0)
                {
                    return null;
                }

                // Pick latest by updated_at
                DateTimeOffset bestUpdated = DateTimeOffset.MinValue;
                string bestId = null;

                foreach (var a in apps.EnumerateArray())
                {
                    string id = null;
                    JsonElement idEl;
                    if (a.TryGetProperty("id", out idEl))
                        id = idEl.GetString();

                    DateTimeOffset? updated = null;
                    JsonElement uEl;
                    if (a.TryGetProperty("updated_at", out uEl))
                    {
                        var s = uEl.GetString();
                        DateTimeOffset dt;
                        if (!string.IsNullOrEmpty(s) && DateTimeOffset.TryParse(s, out dt))
                            updated = dt;
                    }

                    if (!string.IsNullOrEmpty(id))
                    {
                        var cmp = updated.HasValue ? updated.Value : DateTimeOffset.MinValue;
                        if (cmp > bestUpdated)
                        {
                            bestUpdated = cmp;
                            bestId = id;
                        }
                    }
                }

                return bestId;
            }
        }
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
        Console.WriteLine("[STATUS] " + item.FoundationUrl + " | " + item.SpaceName + " | " +
            (string.IsNullOrEmpty(item.AppId) ? "-" : item.AppId) + " | " + item.AppName +
            " => " + outcome + " (" + message + ")");
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

    public StopperOrchestrator(TokenProvider tokens, Func<HttpClient> httpFactory, int maxParallelPerFoundation)
    {
        _tokens = tokens;
        _httpFactory = httpFactory;
        _maxParallelPerFoundation = Math.Max(1, maxParallelPerFoundation);
    }

    public async Task<IReadOnlyCollection<StopResult>> RunAsync(IEnumerable<AppStopItem> items, CancellationToken ct)
    {
        var results = new ConcurrentBag<StopResult>();

        var byFoundation = items.GroupBy(i => i.FoundationUrl);

        foreach (var foundationGroup in byFoundation)
        {
            string foundation = foundationGroup.Key;
            Console.WriteLine();
            Console.WriteLine("=== Processing foundation: " + foundation + " ===");

            // 1) Fetch token once per foundation (with prod/non-prod logic in provider)
            string token = await _tokens.GetTokenAsync(foundation, ct).ConfigureAwait(false);

            // 2) Create a client bound to this foundation
            using (var http = _httpFactory())
            {
                http.BaseAddress = new Uri(foundation);
                var platform = new PlatformClient(http);
                platform.SetBearer(token);

                // 3) Parallelize stops within this foundation
                var throttler = new SemaphoreSlim(_maxParallelPerFoundation);
                var tasks = new List<Task>();

                foreach (var item in foundationGroup)
                {
                    tasks.Add(Task.Run(async () =>
                    {
                        await throttler.WaitAsync(ct).ConfigureAwait(false);
                        try
                        {
                            var res = await HandleOneAsync(platform, item, ct).ConfigureAwait(false);
                            results.Add(res);
                            await StatusUpdater.UpdateAsync(item, res.Outcome, res.Message, ct).ConfigureAwait(false);
                        }
                        finally
                        {
                            throttler.Release();
                        }
                    }, ct));
                }

                await Task.WhenAll(tasks).ConfigureAwait(false);
                throttler.Dispose();
            }
        }

        return results.ToArray();
    }

    private async Task<StopResult> HandleOneAsync(PlatformClient platform, AppStopItem item, CancellationToken ct)
    {
        // Try by ID if present
        if (!string.IsNullOrWhiteSpace(item.AppId))
        {
            var r1 = await platform.StopByIdAsync(item.FoundationUrl, item.AppId, ct).ConfigureAwait(false);
            if (r1.Success)
                return new StopResult(item, r1.AlreadyStopped ? StopOutcome.AlreadyStopped : StopOutcome.StoppedById, r1.Message);

            if (r1.Message == null || r1.Message.IndexOf("not found", StringComparison.OrdinalIgnoreCase) < 0)
                return new StopResult(item, StopOutcome.Failed, r1.Message ?? "Failed stop by id");
        }

        // Lookup by name if ID not provided or not found
        var latestId = await platform.FindLatestIdByNameAsync(item.FoundationUrl, item.SpaceName, item.AppName, ct).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(latestId))
        {
            var r2 = await platform.StopByIdAsync(item.FoundationUrl, latestId, ct).ConfigureAwait(false);
            if (r2.Success)
                return new StopResult(item, r2.AlreadyStopped ? StopOutcome.AlreadyStopped : StopOutcome.StoppedByNameLookup, r2.Message);

            return new StopResult(item, StopOutcome.Failed, r2.Message ?? "Failed after name lookup");
        }

        // Treat not found as success
        return new StopResult(item, StopOutcome.NotFoundTreatedAsSuccess, "App not found; treated as successfully stopped");
    }
}

// ----------------------------
// Program entry
// ----------------------------
public class Program
{
    public static async Task Main(string[] args)
    {
        var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (s, e) => { e.Cancel = true; cts.Cancel(); };

        // EXAMPLE INPUT – replace with your real list
        var items = new List<AppStopItem>
        {
            new AppStopItem("https://foundation-a.example", "space-one",  "app-guid-1", "orders-api"),
            new AppStopItem("https://foundation-a.example", "space-one",  "",           "inventory-ui"),
            new AppStopItem("https://foundation-b.example", "space-prod", "app-guid-9", "payments-api"),
            new AppStopItem("https://foundation-prod.example", "space-prod", "",        "orchestrator")
        };

        // Shared HTTP for token provider
        var sharedHttp = new HttpClient();
        sharedHttp.Timeout = TimeSpan.FromSeconds(60);

        var tokenProvider = new TokenProvider(
            sharedHttp,
            prodClientId:    GetEnv("PCF_PROD_CLIENT_ID",    "prod-client-id"),
            prodClientSecret:GetEnv("PCF_PROD_CLIENT_SECRET","prod-secret"),
            nonProdClientId: GetEnv("PCF_NONPROD_CLIENT_ID", "nonprod-client-id"),
            nonProdClientSecret:GetEnv("PCF_NONPROD_CLIENT_SECRET", "nonprod-secret")
        );

        // Per-request HttpClient factory (replace with IHttpClientFactory in DI if wanted)
        Func<HttpClient> httpFactory = () =>
        {
            var cli = new HttpClient();
            cli.Timeout = TimeSpan.FromSeconds(60);
            return cli;
        };

        var orchestrator = new StopperOrchestrator(tokenProvider, httpFactory, maxParallelPerFoundation: 8);
        var results = await orchestrator.RunAsync(items, cts.Token).ConfigureAwait(false);

        // ----------------------------
        // Final summary
        // ----------------------------
        var grouped = results.GroupBy(r => r.Item.FoundationUrl).OrderBy(g => g.Key);

        Console.WriteLine();
        Console.WriteLine("========== SUMMARY ==========");
        foreach (var g in grouped)
        {
            Console.WriteLine();
            Console.WriteLine("Foundation: " + g.Key);

            var countsByOutcome = new Dictionary<StopOutcome, int>();
            foreach (var r in g)
            {
                int cur;
                countsByOutcome[r.Outcome] = countsByOutcome.TryGetValue(r.Outcome, out cur) ? cur + 1 : 1;
            }

            int ok = GetCount(countsByOutcome, StopOutcome.StoppedById)
                   + GetCount(countsByOutcome, StopOutcome.StoppedByNameLookup)
                   + GetCount(countsByOutcome, StopOutcome.NotFoundTreatedAsSuccess)
                   + GetCount(countsByOutcome, StopOutcome.AlreadyStopped);

            int failed = GetCount(countsByOutcome, StopOutcome.Failed);

            Console.WriteLine("  Success (incl. already stopped & not-found-treated-success): " + ok);
            Console.WriteLine("  Failed: " + failed);

            foreach (var res in g.OrderBy(r => r.Item.SpaceName).ThenBy(r => r.Item.AppName))
            {
                Console.WriteLine("    [" + res.Outcome + "] " + res.Item.SpaceName +
                                  " | " + res.Item.AppName +
                                  " | id=" + (string.IsNullOrEmpty(res.Item.AppId) ? "-" : res.Item.AppId) +
                                  " -> " + res.Message);
            }
        }

        Console.WriteLine();
        Console.WriteLine("All done.");
    }

    private static string GetEnv(string name, string fallback)
    {
        var v = Environment.GetEnvironmentVariable(name);
        return string.IsNullOrEmpty(v) ? fallback : v;
    }

    private static int GetCount(Dictionary<StopOutcome, int> dict, StopOutcome k)
    {
        int v;
        return dict.TryGetValue(k, out v) ? v : 0;
    }
}