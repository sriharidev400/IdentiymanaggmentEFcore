using IdentiyEntiyframework.DataBase;
using IdentiyEntiyframework.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NuGet.Packaging.Core;

namespace IdentiyEntiyframework.Controllers
{
    public class UserController : Controller
    {
        
        private readonly ApplicationDBcontext  _db;
        private readonly UserManager<Applicationuser> _userManager;

        public UserController(ApplicationDBcontext db,UserManager<Applicationuser> userManager)
        {
            _db = db;
            _userManager=userManager;
        }
        public IActionResult Index()
        {
            var userList = _db.Applicationusers.ToList();
            var userRole = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();
            foreach(var user in userList)
            {
                var user_role=userRole.FirstOrDefault(u=>u.UserId==user.Id);
                if (user_role == null)
                {
                    user.Role = "none";
                }else
                {
                    user.Role = roles.FirstOrDefault(u => u.Id == user_role.RoleId).Name;
                }
            }

            return View(userList);
        }
    }
}
