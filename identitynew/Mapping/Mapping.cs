using AutoMapper;
using identitynew.Dtos;
using identitynew.Models;

namespace identitynew.Mapping
{
    public class AuthMappingProfile : Profile
    {
        public AuthMappingProfile()
        {
            CreateMap<RegisterDto, AppUser>();


        }
    }
}