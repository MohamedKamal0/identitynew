using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using identitynew.Interfaces.Auth;
using identitynew.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace identitynew.Services
{
    public class TokenService : ITokenService
    {
        private readonly JwtSettings jwtSettings;
        private readonly ILogger<TokenService> logger;
        private readonly IHttpContextAccessor httpContextAccessor;
        private readonly IDeviceFingerprintService deviceFingerprintService;

        public TokenService(
            IOptions<JwtSettings> options,
            ILogger<TokenService> _logger,
            IHttpContextAccessor httpContextAccessor,
            IDeviceFingerprintService deviceFingerprintService)
        {
            jwtSettings = options.Value;
            logger = _logger;
            this.httpContextAccessor = httpContextAccessor;
            this.deviceFingerprintService = deviceFingerprintService;
        }

        public Task<string> GenerateAccessTokenAsync(AppUser user, IList<string> roles)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub , user.Id ),
                new Claim(JwtRegisteredClaimNames.Email , user.Email ?? string.Empty),
                new Claim(JwtRegisteredClaimNames.Jti ,  Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier  ,user.Id),
                new Claim(ClaimTypes.Email  ,user.Email!),
                new Claim("FirstName" , user.FirstName!),
                new Claim("LastName" , user.LastName!),
                new Claim("security_stamp", user.SecurityStamp ?? string.Empty) // For Single Device Login - invalidates old tokens
            };

            // Device fingerprinting: bind token to current device
            try
            {
                var httpContext = httpContextAccessor.HttpContext;
                if (httpContext != null)
                {
                    var fingerprint = deviceFingerprintService.GetFingerprint(httpContext);
                    claims.Add(new Claim("device_fingerprint", fingerprint));
                }
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to generate device fingerprint. Continuing without fingerprint claim.");
            }

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("SecretKey") ?? jwtSettings.SecretKey));
            var credential = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: jwtSettings.Issuer,
                audience: jwtSettings.Audience,
                claims: claims,
                expires: GetAccessTokenExpiration(),
                signingCredentials: credential
            );
            var writeToken = new JwtSecurityTokenHandler().WriteToken(token);
            return Task.FromResult(writeToken);
        }

        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        public DateTime GetAccessTokenExpiration()
        {
            return DateTime.UtcNow.AddMinutes(jwtSettings.AccessTokenExpirationMinutes);
        }

        public ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = false, // Allow expired tokens
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtSettings.Issuer,
                ValidAudience = jwtSettings.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("SecretKey") ?? jwtSettings.SecretKey))
            };

            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);

                if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                    !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                {
                    return null;
                }

                return principal;
            }
            catch
            {
                return null;
            }
        }

        public DateTime GetRefreshTokenExpiration()
        {
            return DateTime.UtcNow.AddDays(jwtSettings.RefreshTokenExpirationDays);
        }
    }
}
