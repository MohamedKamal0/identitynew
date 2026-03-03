using System.Security.Cryptography;
using System.Text;
using identitynew.Interfaces.Auth;
using Microsoft.AspNetCore.Http;

namespace identitynew.Services
{
    public class DeviceFingerprintService : IDeviceFingerprintService
    {
        public string GetFingerprint(HttpContext httpContext)
        {
            // IP Address (prefer X-Forwarded-For when behind proxy)
            var ip = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault()
                     ?? httpContext.Connection.RemoteIpAddress?.ToString()
                     ?? "unknown-ip";

            // User-Agent / Browser
            var userAgent = httpContext.Request.Headers["User-Agent"].FirstOrDefault()
                            ?? "unknown-ua";

            // OS (simple heuristic from User-Agent)
            var os = "unknown-os";
            var uaLower = userAgent.ToLowerInvariant();
            if (uaLower.Contains("windows")) os = "windows";
            else if (uaLower.Contains("mac os") || uaLower.Contains("macintosh")) os = "macos";
            else if (uaLower.Contains("android")) os = "android";
            else if (uaLower.Contains("iphone") || uaLower.Contains("ipad") || uaLower.Contains("ios")) os = "ios";
            else if (uaLower.Contains("linux")) os = "linux";

            var raw = $"{ip}|{userAgent}|{os}";

            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(raw);
            var hash = sha256.ComputeHash(bytes);

            return Convert.ToBase64String(hash);
        }
    }
}

