using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentiyEntiyframework.Controllers
{
    [Authorize]
    public class AccessCheckerController : Controller
    {
        //Any one can access this
        [AllowAnonymous]
        public IActionResult AllAccess()
        {
            return View();
        }
        //Any one that has logged in can access
        public IActionResult AuthorizedAccess()
        {
            return View();
        }
        //account  with role of user can access
        [Authorize(Roles =$"{SD.Admin},{SD.User}")]
        public IActionResult UserORAdminRoleAccess()
        {
            return View();
        }
        //account with role of user or admin can access
        [Authorize(Policy = "AdminAndUser")]
        public IActionResult UserANDAdminRoleAccess()
        {
            return View();
        }
        [Authorize(Policy =SD.Admin)]
         public IActionResult AdminRoleAccess()
        {
            return View();
        }
        // account with admin role and create claim can  access
        public IActionResult AdminCreateAccess()
        {
            return View();
        }
        // account with admin role and (create and edit and delete) claim can  access
        [Authorize(Policy = "Admin_Create_Edit_DeleteAccess")]
        public IActionResult Admin_Create_Edit_DeleteAccess()
        {
            return View();
        }
        [Authorize(Policy="AdminRole_Createclaim")]
        public IActionResult Admin_CreateAccess()
        {
            return View();
        }
    }
}
