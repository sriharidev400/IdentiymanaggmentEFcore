using IdentiyEntiyframework.Models;
using IdentiyEntiyframework.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;

namespace IdentiyEntiyframework.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<Applicationuser> _userManager;
        
        private readonly SignInManager<Applicationuser> _signInManager;

        public AccountController(UserManager<Applicationuser> userManager, 
             SignInManager<Applicationuser> signInManager
            )
        {
            
        }
        public IActionResult Register()
        {
            RegisterViewModel registerViewModel = new();
            return View(registerViewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new Applicationuser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    Name = model.Name
                };
                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded) { 
                 await _signInManager.SignInAsync(user, isPersistent: false);
                    return RedirectToAction("Index", "Home");
                }
            }
            return View(model);
        }
    }
}
