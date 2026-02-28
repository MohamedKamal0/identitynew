using System.Security.Claims;
using identitynew.Models;

namespace identitynew.Interfaces.Auth
{
    public interface ITokenService
    {
        Task<string> GenerateAccessTokenAsync(AppUser user, IList<string> roles);
        string GenerateRefreshToken();
        ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
        DateTime GetAccessTokenExpiration();
        DateTime GetRefreshTokenExpiration();
    }
}
