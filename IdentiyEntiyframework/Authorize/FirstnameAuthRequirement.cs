using Microsoft.AspNetCore.Authorization;
namespace IdentiyEntiyframework.Authorize
{
    public class FirstnameAuthRequirement : IAuthorizationRequirement
    {
        public FirstnameAuthRequirement(string name)
        {
            Name= name;
        }
        public string Name { get; set; }
    }
}
