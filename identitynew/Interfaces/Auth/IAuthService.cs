using identitynew.Dtos;
using identitynew.Response;

namespace identitynew.Interfaces.Auth
{
    public interface IAuthService
    {
        Task<RegisterResponse> RegisterAsync(RegisterDto registerDto);
        Task<LoginResponse> LoginAsync(LoginDto loginDto);
        Task<RefreshTokenResponse> RefreshTokenAsync(RefreshTokenDto refreshTokenDto);
        Task<LogoutResponse> LogoutAsync(string userId);
        Task<ForgetPasswordResponse> ForgetPasswordAsync(ForgotPasswordDto forgotPasswordDto);
        Task<ResetPasswordResponse> ResetPasswordAsync(ResetPasswordDto resetPasswordDto);
        Task<ChangePasswordResponse> ChangePasswordAsync(string userId, ChangePasswordDto changePasswordDto);

    }
}
