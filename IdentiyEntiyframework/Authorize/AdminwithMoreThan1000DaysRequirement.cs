using Microsoft.AspNetCore.Authorization;
namespace IdentiyEntiyframework.Authorize
{
    public class AdminwithMoreThan1000DaysRequirement:IAuthorizationRequirement
    {
        public AdminwithMoreThan1000DaysRequirement(int days)
        {
            Days = days;
        }
        public int Days { get; set; }
    }
}
