# Hitachi Content Platform (HCP) – Namespace IP Allow/Deny List Management (MAPI)

This document explains how to use the Hitachi Content Platform (HCP) Management API (MAPI) to:

- List namespaces under a tenant
- Read current IP allow/deny lists for a namespace
- Update allowlist / denylist IPs for namespace protocols (HTTP/WebDAV)
- Understand which HTTP method is required (POST, not PUT or PATCH)
- Perform operations using cURL or .NET (C#)

---

## 1. Prerequisites

- HCP Management API (MAPI) must be enabled:
  - At the system / cluster level
  - At the tenant level (if using tenant admin credentials)
- Tenant admin or system admin credentials
- Access to the Admin endpoint (usually port 9090)
- HTTPS is recommended

---

## 2. Base URL Format

https://<hcp-admin-host>:9090/mapi

Example:

https://admin.hcp.example.com:9090/mapi

---

## 3. Authentication

HCP MAPI uses a custom Authorization header.

Token format:

base64(username):md5(password)

Authorization header:

Authorization: HCP <token>

Example:

Authorization: HCP bGdyZWVu:2a9d8c6e3f...

---

## 4. List Namespaces for a Tenant

Endpoint:

GET /mapi/tenants/{tenant-name}/namespaces

Example (cURL):

curl -k \
  -H "Accept: application/json" \
  -H "Authorization: HCP <token>" \
  "https://admin.hcp.example.com:9090/mapi/tenants/finance/namespaces"

Response:

[
  "accounts-receivable",
  "billing",
  "audit-logs"
]

---

## 5. Read Namespace Protocol Configuration (IP Allow/Deny Lists)

IP allow/deny lists are defined per protocol.

Endpoint:

GET /mapi/tenants/{tenant}/namespaces/{namespace}/protocols/{protocol}

Supported protocol values:
- http (includes WebDAV)
- nfs
- cifs
- smtp

Example:

curl -k \
  -H "Accept: application/json" \
  -H "Authorization: HCP <token>" \
  "https://admin.hcp.example.com:9090/mapi/tenants/finance/namespaces/accounts-receivable/protocols/http"

Relevant response section:

{
  "ipSettings": {
    "allowAddresses": {
      "ipAddress": [
        "192.168.140.10",
        "192.168.149.0/24"
      ]
    },
    "denyAddresses": {
      "ipAddress": [
        "192.168.149.5"
      ]
    },
    "allowIfInBothLists": false
  }
}

---

## 6. Updating IP Allow/Deny Lists

Important: Updating IP allow/deny lists uses POST.

- PUT is not supported
- PATCH is not supported
- POST is required

---

## 7. Update IP Allow/Deny List (HTTP / WebDAV)

Endpoint:

POST /mapi/tenants/{tenant}/namespaces/{namespace}/protocols/http

Payload structure:

{
  "ipSettings": {
    "allowAddresses": {
      "ipAddress": [ "<ip-or-cidr>", "..." ]
    },
    "denyAddresses": {
      "ipAddress": [ "<ip-or-cidr>", "..." ]
    },
    "allowIfInBothLists": false
  }
}

Example (cURL):

curl -k -i \
  -H "Content-Type: application/json" \
  -H "Authorization: HCP <token>" \
  -d '{
    "ipSettings": {
      "allowAddresses": {
        "ipAddress": [
          "10.10.10.0/24",
          "192.168.1.25"
        ]
      },
      "denyAddresses": {
        "ipAddress": [
          "10.10.10.99"
        ]
      },
      "allowIfInBothLists": false
    }
  }' \
  "https://admin.hcp.example.com:9090/mapi/tenants/finance/namespaces/accounts-receivable/protocols/http"

---

## 8. Common Mistakes

- Using PUT or PATCH instead of POST
- Updating the namespace root instead of the protocol endpoint
- Sending the full protocol configuration instead of only ipSettings

---

## 9. Recommended Safe Update Pattern

1. GET the current protocol configuration
2. Merge IP addresses in code
3. POST the updated ipSettings

---

## 10. .NET (C#) Example

Build Authorization Header:

using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

static string ToBase64(string s) =>
    Convert.ToBase64String(Encoding.UTF8.GetBytes(s));

static string Md5Hex(string s)
{
    var bytes = Encoding.UTF8.GetBytes(s);
    var hash = MD5.HashData(bytes);
    var sb = new StringBuilder(hash.Length * 2);
    foreach (var b in hash)
        sb.Append(b.ToString("x2"));
    return sb.ToString();
}

static string BuildHcpAuthHeader(string username, string password) =>
    $"HCP {ToBase64(username)}:{Md5Hex(password)}";

List namespaces:

using var http = new HttpClient(new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = (_, _, _, _) => true
});

http.DefaultRequestHeaders.Authorization =
    AuthenticationHeaderValue.Parse(
        BuildHcpAuthHeader("tenant-admin", "password"));

http.DefaultRequestHeaders.Accept.Add(
    new MediaTypeWithQualityHeaderValue("application/json"));

var url = "https://admin.hcp.example.com:9090/mapi/tenants/finance/namespaces";
var response = await http.GetStringAsync(url);

Console.WriteLine(response);

---

## 11. Summary

- Namespace IP allow/deny lists are configured per protocol
- Updates are done using POST
- ipSettings supports allow lists, deny lists, CIDR ranges, and conflict handling
- Always update the protocol endpoint, not the namespace root

---

## 12. References

- Hitachi Content Platform – Management API Reference
- HCP System Administration Guide
- HCP Tenant Administration Guide