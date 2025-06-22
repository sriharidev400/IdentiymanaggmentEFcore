using Microsoft.AspNetCore.Mvc;

namespace IdentiyEntiyframework.Controllers
{
    public class AccessCheckerController : Controller
    {
        //Any one can access this
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
        public IActionResult UserRoleAccess()
        {
            return View();
        }
        //account with role of admin can access
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
        public IActionResult Admin_Create_Edit_DeleteAccess()
        {
            return View();
        }
    }
}
