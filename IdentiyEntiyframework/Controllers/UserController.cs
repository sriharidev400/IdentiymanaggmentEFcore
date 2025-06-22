using IdentiyEntiyframework.DataBase;
using IdentiyEntiyframework.Models;
using IdentiyEntiyframework.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NuGet.Packaging.Core;
using System.Security.Claims;

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
        public async Task<IActionResult> Index()
        {
            var userList = _db.Applicationusers.ToList();
            foreach(var user in userList)
            {
                var user_role = await _userManager.GetRolesAsync(user) as List<string>;
                user.Role = string.Join(",", user_role);
                var user_claim =  _userManager.GetClaimsAsync(user).GetAwaiter().GetResult().Select(u=>u.Type);
                user.UserClaim = string.Join(",", user_claim);

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


        public async Task<IActionResult> ManageUserClaim(string userId)
        {
            Applicationuser user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }
            var exsitingUserClaims = await _userManager.GetClaimsAsync(user);
            var model = new ClaimsViewModel()
            {
                User = user
            };
            foreach (Claim claim in ClaimStore.claimsList)
            {
                ClaimSelection userClaim = new()
                {
                    ClaimType= claim.Type
                };
                if (exsitingUserClaims.Any(c => c.Type == claim.Type))
                {
                    userClaim.IsSelected = true;
                }
                model.ClaimList.Add(userClaim);
            }
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageUserClaim(ClaimsViewModel cailmsViewModel)
        {
            Applicationuser user = await _userManager.FindByIdAsync(cailmsViewModel.User.Id);
            if (user == null)
            {
                return NotFound();
            }
            var oldClaims = await _userManager.GetClaimsAsync(user);
            var result = await _userManager.RemoveClaimsAsync(user, oldClaims);
            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error while removing claims";
                return View(cailmsViewModel);
            }
            result = await _userManager.AddClaimsAsync(user,
               cailmsViewModel.ClaimList.Where(x => x.IsSelected).Select(y => new Claim(y.ClaimType, y.IsSelected.ToString())));

            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error while adding claim";
                return View(cailmsViewModel);
            }
            TempData[SD.Success] = "Claims assigned sucessfully";
            return RedirectToAction(nameof(Index));
        }

    }
}
