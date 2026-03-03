using Microsoft.AspNetCore.Http;

namespace identitynew.Interfaces.Auth
{
    public interface IDeviceFingerprintService
    {
        /// <summary>
        /// Generates a stable fingerprint for the current device based on IP address, User-Agent and OS.
        /// </summary>
        /// <param name="httpContext">The current HTTP context.</param>
        /// <returns>A hashed device fingerprint string.</returns>
        string GetFingerprint(HttpContext httpContext);
    }
}

