using IdentiyEntiyframework.Models.ViewModels;
using Microsoft.AspNetCore.Mvc;

namespace IdentiyEntiyframework.Controllers
{
    public class AccountController : Controller
    {
        public IActionResult Register()
        {
            RegisterViewModel registerViewModel = new();
            return View(registerViewModel);
        }
    }
}
