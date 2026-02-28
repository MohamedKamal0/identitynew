using Microsoft.AspNetCore.Identity;

namespace identitynew.Models
{
    public class AppUser : IdentityUser
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public bool IsVerified { get; set; } = false;
        public bool IsPrivate { get; set; } = false;
        public bool IsActive { get; set; } = true;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? UpdatedAt { get; set; }
        public string? FullName => $"{FirstName} {LastName}".Trim();
        //Navigation Properties
        public List<RefreshToken> RefreshTokens { get; set; }

    }
}
