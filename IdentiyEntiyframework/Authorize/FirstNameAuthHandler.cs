using IdentiyEntiyframework.DataBase;
using IdentiyEntiyframework.Models;
using IdentiyEntiyframework.Services;
using IdentiyEntiyframework.Services.IServices;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace IdentiyEntiyframework.Authorize
{
    public class FirstNameAuthHandler : AuthorizationHandler<FirstnameAuthRequirement>
    {
        public UserManager<Applicationuser> _usermanager {  get; set; }
        public ApplicationDBcontext _db {  get; set; }
        public FirstNameAuthHandler(UserManager<Applicationuser> userManager,ApplicationDBcontext db)
        {
            _db= db;
            _usermanager = userManager;
        }
       

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, FirstnameAuthRequirement requirement)
        {

            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var user = _db.Applicationusers.FirstOrDefault(u => u.Id == userId);
            if (user != null)
            {


                var firstNameclaim = _usermanager.GetClaimsAsync(user)
                    .GetAwaiter().GetResult()
                    .FirstOrDefault(u => u.Type == "FirstName");
                if (firstNameclaim != null)
                {
                    if (firstNameclaim.Value.ToLower().Contains(requirement.Name.ToLower()))
                    {
                        context.Succeed(requirement);

                    }
                }
            }
            return Task.CompletedTask;
        }
    }
}
