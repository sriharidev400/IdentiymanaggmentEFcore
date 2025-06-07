using IdentiyEntiyframework.DataBase;
using IdentiyEntiyframework.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NuGet.Packaging.Core;

namespace IdentiyEntiyframework.Controllers
{
    public class RoleController : Controller
    {
        
        private readonly ApplicationDBcontext  _db;
        private readonly UserManager<Applicationuser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public RoleController(ApplicationDBcontext db,
            UserManager<Applicationuser> userManager,
            RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _userManager = userManager;
            _roleManager = roleManager;
        }
        public IActionResult Index()
        {
            
            var roles = _db.Roles.ToList();
           

            return View(roles);
        }
        [HttpGet]
        public IActionResult Upsert(string roleId)
        {
            if (String.IsNullOrEmpty(roleId))
            {
                //create
                return View();
            }
            else
            {
                //update
                var objFromDb = _db.Roles.FirstOrDefault(u => u.Id == roleId);
                return View(objFromDb);
            }
        }
    }
}
