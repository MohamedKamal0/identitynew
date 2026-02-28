using System.Security.Claims;
using identitynew.Dtos;
using identitynew.Interfaces.Auth;
using identitynew.Response;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace identitynew.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService) : ControllerBase
    {


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
        public async Task<ActionResult<LoginResponse>> Login(LoginDto loginDto)
        {
            var result = await authService.LoginAsync(loginDto);
            if (!result.Succeeded)
            {
                return BadRequest(result);
            }
            return Ok(result);
        }


        //GetNewAccessToken
        [HttpPost("refresh-token")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<RefreshTokenResponse>> GetNewAccessToken(RefreshTokenDto tokenRequest)
        {
            var result = await authService.RefreshTokenAsync(tokenRequest);
            if (!result.Succeeded)
            {
                return BadRequest(result);
            }
            return Ok(result);
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


    }
}

