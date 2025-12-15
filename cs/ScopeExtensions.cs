using System.Security.Claims;

namespace QueryGateway.Auth;

public static class ScopeExtensions
{
    public static bool HasAnyScope(this ClaimsPrincipal user, params string[] required)
    {
        if (required is null || required.Length == 0) return true;

        var scopes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Common claim types
        foreach (var claimType in new[] { "scope", "scp" })
        {
            foreach (var c in user.FindAll(claimType))
            {
                // Handles both: "a b c" and single values
                var parts = c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                foreach (var p in parts) scopes.Add(p);
            }
        }
        
        if (scopes.Contains("canReadAll")) return true;

        return required.Any(scopes.Contains);
    }
}
