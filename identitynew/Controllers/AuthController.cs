using System.Security.Claims;
using identitynew.Dtos;
using identitynew.Interfaces.Auth;
using identitynew.Models;
using identitynew.Response;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace identitynew.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService authService;
        private readonly JwtSettings jwtSettings;

        private const string AccessTokenCookieName = "access_token";
        private const string RefreshTokenCookieName = "refresh_token";

        public AuthController(IAuthService authService, IOptions<JwtSettings> jwtOptions)
        {
            this.authService = authService;
            jwtSettings = jwtOptions.Value;
        }

        [HttpPost("register")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<RegisterResponse>> RegisterUser(RegisterDto registerDto)
        {
            var result = await authService.RegisterAsync(registerDto);
            if (!result.Succeeded)
            {
                return BadRequest(result);
            }
            return Ok(result);
        }

        //Login
        [HttpPost("Login")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<object>> Login(LoginDto loginDto)
        {
            var result = await authService.LoginAsync(loginDto);
            if (!result.Succeeded)
            {
                return BadRequest(result);
            }

            SetAuthCookies(result.AccessToken, result.RefreshToken, result.AccessTokenExpiration, result.RefreshTokenExpiration);

            // Do not expose tokens in the response body – return only user info
            var responseBody = new
            {
                result.UserId,
                result.Email,
                result.FullName,
                result.Roles,
                result.Message
            };

            return Ok(responseBody);
        }

        //GetNewAccessToken
        [HttpPost("refresh-token")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<object>> GetNewAccessToken(RefreshTokenDto tokenRequest)
        {
            // Prefer cookies if body is empty – browser flow
            if (string.IsNullOrEmpty(tokenRequest.Token) && string.IsNullOrEmpty(tokenRequest.RefreshToken))
            {
                var accessTokenFromCookie = Request.Cookies[AccessTokenCookieName];
                var refreshTokenFromCookie = Request.Cookies[RefreshTokenCookieName];

                tokenRequest.Token = accessTokenFromCookie;
                tokenRequest.RefreshToken = refreshTokenFromCookie;
            }

            var result = await authService.RefreshTokenAsync(tokenRequest);
            if (!result.Succeeded)
            {
                return BadRequest(result);
            }

            SetAuthCookies(result.AccessToken, result.RefreshToken, result.AccessTokenExpiration, result.RefreshTokenExpiration);

            // Do not expose raw tokens in body
            var responseBody = new
            {
                result.Message,
                result.AccessTokenExpiration,
                result.RefreshTokenExpiration
            };

            return Ok(responseBody);
        }

        //Logout
        [HttpPost("Logout")]
        [Authorize]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<IActionResult> Logout()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized();
            }
            var result = await authService.LogoutAsync(userId);
            if (!result.Succeeded)
            {
                return BadRequest(result);
            }

            ClearAuthCookies();

            return Ok(result);
        }

        //ForgotPassword
        [HttpPost("Forget-password")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<ForgetPasswordResponse>> ForgetPassword([FromBody] ForgotPasswordDto forgotPasswordDto)
        {
            var user = await authService.ForgetPasswordAsync(forgotPasswordDto);
            if (!user.Succeeded)
            {
                return BadRequest(user);
            }
            return Ok(user);
        }

        [HttpPost("reset-password")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto resetPasswordDto)
        {
            var result = await authService.ResetPasswordAsync(resetPasswordDto);
            if (!result.Succeeded)
            {
                return BadRequest(result);
            }
            return Ok(result);
        }

        private void SetAuthCookies(string accessToken, string refreshToken, DateTime? accessTokenExpiration, DateTime? refreshTokenExpiration)
        {
            if (!string.IsNullOrEmpty(accessToken) && accessTokenExpiration.HasValue)
            {
                Response.Cookies.Append(AccessTokenCookieName, accessToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = accessTokenExpiration
                });
            }

            if (!string.IsNullOrEmpty(refreshToken) && refreshTokenExpiration.HasValue)
            {
                Response.Cookies.Append(RefreshTokenCookieName, refreshToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = refreshTokenExpiration
                });
            }
        }

        private void ClearAuthCookies()
        {
            Response.Cookies.Delete(AccessTokenCookieName);
            Response.Cookies.Delete(RefreshTokenCookieName);
        }
    }
}

