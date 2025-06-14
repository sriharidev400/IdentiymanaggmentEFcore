using IdentiyEntiyframework.DataBase;
using IdentiyEntiyframework.Models;
using IdentiyEntiyframework.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NuGet.Packaging.Core;

namespace IdentiyEntiyframework.Controllers
{
    public class UserController : Controller
    {
        
        private readonly ApplicationDBcontext  _db;
        private readonly UserManager<Applicationuser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserController(ApplicationDBcontext db,
            UserManager<Applicationuser> userManager,
            RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _userManager = userManager;
            _roleManager = roleManager;
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

        public async Task<IActionResult> ManageRole(string userId)
        {
            Applicationuser user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }
            List<string> exsitingUserRoles = await _userManager.GetRolesAsync(user) as List<string>;
            var model = new RolesViewModel()
            {
                User = user
            };
            foreach(var role in _roleManager.Roles)
            {
                RoleSelection roleSelection = new()
                {
                    RoleName = role.Name
                };
                if (exsitingUserRoles.Any(c => c == role.Name))
                {
                    roleSelection.IsSelected = true;
                }
               model.RolesList.Add(roleSelection);
            }
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageRole(RolesViewModel rolesViewModel)
        {
            Applicationuser user = await _userManager.FindByIdAsync(rolesViewModel.User.Id);
            if (user == null)
            {
                return NotFound();
            }
           var  oldUserRoles = await _userManager.GetRolesAsync(user);
            var result = await _userManager.RemoveFromRolesAsync(user, oldUserRoles);
            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error while Removing roles";
                return View(rolesViewModel);
            }
            result = await _userManager.AddToRolesAsync(user,
                rolesViewModel.RolesList.Where(x => x.IsSelected).Select(Y => Y.RoleName));
            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error while adding roles";
                return View(rolesViewModel);
            }
            TempData[SD.Success] = "Roles assigned sucessfully";
            return RedirectToAction(nameof(Index));
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LockUnlock(string userId)
        {
            Applicationuser user = _db.Applicationusers.FirstOrDefault(u=>u.Id== userId);
            if (user == null)
            {
                return NotFound();
            }
            if(user.LockoutEnd !=null && user.LockoutEnd > DateTime.Now)
            {
                user.LockoutEnd = DateTime.Now;
                TempData[SD.Success] = "User unlocked sucessfully";
            }
            else
            {
                user.LockoutEnd = DateTime.Now.AddYears(1000);
                TempData[SD.Success] = "User locked sucessfully";
            }
            _db.SaveChanges();

            return RedirectToAction(nameof(Index));
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult DeleteUser(string userId)
        {
            var user = _db.Applicationusers.FirstOrDefault(u => u.Id == userId);
            if (user == null)
            {
                return NotFound();
            }
            _db.Applicationusers.Remove(user);
            _db.SaveChanges();
            TempData[SD.Success] = "user deleted successfuly";
            return RedirectToAction(nameof(Index));
        }

    }
}
