<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="YamlDotNet" Version="15.1.4" />
    <PackageReference Include="ClosedXML" Version="0.102.2" />
    <PackageReference Include="System.Net.Http.Json" Version="8.0.0" />
  </ItemGroup>
</Project>






using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using YamlDotNet.RepresentationModel;
using ClosedXML.Excel;

const string RepoPrefix = "cf-mgmt-config-";

var argsDict = ParseArgs(args);
string Required(string key) =>
    argsDict.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v)
        ? v! : throw new ArgumentException($"Missing --{key}");

string? Optional(string key) =>
    argsDict.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v) ? v : null;

var org = Required("org");
var baseUrl = Optional("baseUrl") ?? "https://api.github.com"; // will be normalized below
var outPath = Optional("out") ?? "missing-orgs.xlsx";
var dop = int.TryParse(Optional("dop"), out var p) ? Math.Max(1, p) : 8;
var verifySsl = !string.Equals(Optional("verifySsl"), "false", StringComparison.OrdinalIgnoreCase);

var token = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
if (string.IsNullOrWhiteSpace(token))
{
    Console.Error.WriteLine("ERROR: Set GITHUB_TOKEN environment variable.");
    return;
}

// Normalize base URL (Enterprise: https://yourhost/api/v3)
if (!baseUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase))
    baseUrl = "https://" + baseUrl;

if (baseUrl.EndsWith("/")) baseUrl = baseUrl.TrimEnd('/');

// If caller passed a plain GHE host, append /api/v3
if (!baseUrl.Contains("/api/"))
    baseUrl = baseUrl + "/api/v3";

Console.WriteLine($"Org: {org}");
Console.WriteLine($"API Base: {baseUrl}/");
Console.WriteLine($"Output: {outPath}");
Console.WriteLine($"Parallelism: {dop}");
Console.WriteLine($"Verify SSL: {verifySsl}");

var handler = new HttpClientHandler();
if (!verifySsl)
{
    handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("[WARN] SSL verification disabled. Prefer installing your corporate root CA.");
    Console.ResetColor();
}

using var http = new HttpClient(handler)
{
    BaseAddress = new Uri(baseUrl + "/")
};
http.DefaultRequestHeaders.UserAgent.ParseAdd("cf-mgmt-config-audit/1.1");
http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

var results = new ConcurrentBag<(string Foundation, string Org)>();

// 1) List repos with prefix
var repos = await GetAllReposAsync(http, org);
var targetRepos = repos.Where(r => r.name.StartsWith(RepoPrefix, StringComparison.OrdinalIgnoreCase)).ToList();
Console.WriteLine($"Found {targetRepos.Count} repos with prefix '{RepoPrefix}'");

await ParallelForEachAsync(targetRepos, dop, async repo =>
{
    var foundation = repo.name.Substring(RepoPrefix.Length);
    try
    {
        // 2) Load org.yml (or orgs.yml)
        string? yaml = await GetFileContentAsync(http, org, repo.name, "org.yml")
                      ?? await GetFileContentAsync(http, org, repo.name, "orgs.yml");

        if (yaml == null)
        {
            Console.WriteLine($"[WARN] {repo.name}: org.yml/orgs.yml not found.");
            return;
        }

        var orgsFromYaml = ParseOrgNamesFromYaml(yaml);
        if (orgsFromYaml.Count == 0)
        {
            Console.WriteLine($"[WARN] {repo.name}: no orgs parsed.");
            return;
        }

        // 3) Root entries -> folder names
        var root = await GetRootEntriesAsync(http, org, repo.name);
        var topFolders = root.Where(e => e.type.Equals("dir", StringComparison.OrdinalIgnoreCase))
                             .Select(e => e.name)
                             .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var o in orgsFromYaml)
        {
            if (!topFolders.Contains(o))
                results.Add((foundation, o));
        }
    }
    catch (HttpRequestException hex)
    {
        Console.WriteLine($"[ERROR] {repo.name}: {hex.Message}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[ERROR] {repo.name}: {ex}");
    }
});

Console.WriteLine($"Missing folder rows: {results.Count}");
WriteExcel(outPath, results.OrderBy(r => r.Foundation).ThenBy(r => r.Org));
Console.WriteLine($"Done. Wrote {outPath}");

// ----------------- Helpers -----------------
static async Task<List<(string name, bool isPrivate)>> GetAllReposAsync(HttpClient http, string org)
{
    var all = new List<(string name, bool isPrivate)>();
    var page = 1;
    const int perPage = 100;

    while (true)
    {
        var url = $"orgs/{org}/repos?per_page={perPage}&page={page}&sort=full_name&direction=asc";
        using var resp = await http.GetAsync(url);
        resp.EnsureSuccessStatusCode();

        using var stream = await resp.Content.ReadAsStreamAsync();
        using var json = await JsonDocument.ParseAsync(stream);

        var batch = new List<(string, bool)>();
        foreach (var item in json.RootElement.EnumerateArray())
        {
            var name = item.GetProperty("name").GetString()!;
            var isPrivate = item.GetProperty("private").GetBoolean();
            batch.Add((name, isPrivate));
        }

        if (batch.Count == 0) break;
        all.AddRange(batch);

        // Stop when fewer than perPage items returned (cheap pagination)
        if (batch.Count < perPage) break;
        page++;
    }
    return all;
}

static async Task<string?> GetFileContentAsync(HttpClient http, string owner, string repo, string path)
{
    var url = $"repos/{owner}/{repo}/contents/{Uri.EscapeDataString(path)}";
    using var resp = await http.GetAsync(url);
    if (resp.StatusCode == System.Net.HttpStatusCode.NotFound) return null;
    resp.EnsureSuccessStatusCode();

    using var stream = await resp.Content.ReadAsStreamAsync();
    using var json = await JsonDocument.ParseAsync(stream);

    if (!json.RootElement.TryGetProperty("content", out var contentProp))
        return null;

    var base64 = (contentProp.GetString() ?? string.Empty).Replace("\n", string.Empty);
    var bytes = Convert.FromBase64String(base64);
    return Encoding.UTF8.GetString(bytes);
}

static async Task<List<(string name, string type)>> GetRootEntriesAsync(HttpClient http, string owner, string repo)
{
    var url = $"repos/{owner}/{repo}/contents";
    using var resp = await http.GetAsync(url);
    resp.EnsureSuccessStatusCode();

    using var stream = await resp.Content.ReadAsStreamAsync();
    using var json = await JsonDocument.ParseAsync(stream);

    var list = new List<(string, string)>();
    foreach (var item in json.RootElement.EnumerateArray())
    {
        list.Add((item.GetProperty("name").GetString()!,
                  item.GetProperty("type").GetString()!));
    }
    return list;
}

static HashSet<string> ParseOrgNamesFromYaml(string yamlText)
{
    var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    var yaml = new YamlStream();
    using var reader = new StringReader(yamlText);
    yaml.Load(reader);

    if (yaml.Documents.Count == 0) return result;

    var root = yaml.Documents[0].RootNode;
    if (root is YamlMappingNode map)
    {
        if (map.Children.TryGetValue(new YamlScalarNode("orgs"), out var orgsNode) &&
            orgsNode is YamlSequenceNode seq)
        {
            ExtractFromSequence(seq, result);
        }
    }
    else if (root is YamlSequenceNode seqRoot)
    {
        ExtractFromSequence(seqRoot, result);
    }
    return result;

    static void ExtractFromSequence(YamlSequenceNode seq, HashSet<string> acc)
    {
        foreach (var item in seq.Children)
        {
            switch (item)
            {
                case YamlScalarNode s when !string.IsNullOrWhiteSpace(s.Value):
                    acc.Add(s.Value.Trim());
                    break;
                case YamlMappingNode m:
                    if (m.Children.TryGetValue(new YamlScalarNode("name"), out var n) &&
                        n is YamlScalarNode ns &&
                        !string.IsNullOrWhiteSpace(ns.Value))
                    {
                        acc.Add(ns.Value.Trim());
                    }
                    break;
            }
        }
    }
}

static void WriteExcel(string path, IEnumerable<(string Foundation, string Org)> rows)
{
    using var wb = new XLWorkbook();
    var ws = wb.Worksheets.Add("MissingOrgs");
    ws.Cell(1, 1).Value = "Foundation";
    ws.Cell(1, 2).Value = "Org";

    var r = 2;
    foreach (var row in rows)
    {
        ws.Cell(r, 1).Value = row.Foundation;
        ws.Cell(r, 2).Value = row.Org;
        r++;
    }

    ws.Range(1, 1, Math.Max(1, r - 1), 2).SetAutoFilter();
    ws.Columns().AdjustToContents();
    wb.SaveAs(path);
}

static async Task ParallelForEachAsync<T>(IEnumerable<T> source, int maxDop, Func<T, Task> body)
{
    using var sem = new SemaphoreSlim(maxDop);
    var tasks = new List<Task>();
    foreach (var item in source)
    {
        await sem.WaitAsync();
        tasks.Add(Task.Run(async () =>
        {
            try { await body(item); }
            finally { sem.Release(); }
        }));
    }
    await Task.WhenAll(tasks);
}

static Dictionary<string, string?> ParseArgs(string[] a)
{
    var map = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
    for (int i = 0; i < a.Length; i++)
    {
        if (a[i].StartsWith("--"))
        {
            var key = a[i][2..];
            string? val = null;
            if (i + 1 < a.Length && !a[i + 1].StartsWith("--"))
                val = a[++i];
            map[key] = val;
        }
    }
    return map;
}