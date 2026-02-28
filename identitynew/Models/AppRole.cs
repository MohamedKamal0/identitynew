using Microsoft.AspNetCore.Identity;

namespace identitynew.Models
{
    public class AppRole : IdentityRole<string>
    {
        public AppRole() : base()
        { }
        public AppRole(string roleName) : base(roleName)
        {
            Id = Guid.NewGuid().ToString();
        }
        public AppRole(string roleName, string description) : base(roleName)
        {
            Id = Guid.NewGuid().ToString();
            Description = description;
        }
        public string Description { get; set; }
    }
}
