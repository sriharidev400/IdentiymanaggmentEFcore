using IdentiyEntiyframework.Services.IServices;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace IdentiyEntiyframework.Authorize
{
    public class AdminOver1000DaysHandler : AuthorizationHandler<AdminwithMoreThan1000DaysRequirement>
    {
        private readonly INumberOfDaysForAccount _numberOfDaysForAccount;
        public AdminOver1000DaysHandler(INumberOfDaysForAccount numberOfDaysForAccount)
        {
            _numberOfDaysForAccount= numberOfDaysForAccount;
        }
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AdminwithMoreThan1000DaysRequirement requirement)
        {
            if (!context.User.IsInRole(SD.Admin))
            {
                return Task.CompletedTask;
            }
            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier).Value;
            var numberofDays = _numberOfDaysForAccount.Get(userId);
            if (numberofDays >= requirement.Days)
            {
                context.Succeed(requirement);
            }
            return Task.CompletedTask;
        }
    }
}
