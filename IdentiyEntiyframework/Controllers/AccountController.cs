using IdentiyEntiyframework.Models;
using IdentiyEntiyframework.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace IdentiyEntiyframework.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly UserManager<Applicationuser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<Applicationuser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly UrlEncoder _urlEncoder;
        public AccountController(UserManager<Applicationuser> userManager, 
             SignInManager<Applicationuser> signInManager,
             IEmailSender emailSender, UrlEncoder urlEncoder, RoleManager<IdentityRole> roleManager
            )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _urlEncoder = urlEncoder;
            _roleManager = roleManager;

        }
        [AllowAnonymous]
        public async Task<IActionResult> Register(string returnurl = null)
        {
            if(!_roleManager.RoleExistsAsync(SD.Admin).GetAwaiter().GetResult())
            {
                await _roleManager.CreateAsync(new IdentityRole(SD.Admin));
                await _roleManager.CreateAsync(new IdentityRole(SD.User));
            }
            
            ViewData["ReturnUrl"] = returnurl;
            RegisterViewModel registerViewModel = new()
            {
                RoleList = _roleManager.Roles.Select(x => x.Name).Select(i => new SelectListItem
                {
                    Text=i,
                    Value=i
                })
            };
            return View(registerViewModel);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                var user = new Applicationuser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    Name = model.Name,
                    DateCreated = DateTime.Now
                };
                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded) {
                    if(model.RoleSelected!=null)
                    {
                        await _userManager.AddToRoleAsync(user, model.RoleSelected);
                    }
                    else
                    {
                        await _userManager.AddToRoleAsync(user, SD.User);
                    }
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var callbackurl = Url.Action("ConfirmEmail", "Account", new
                    {
                        userid = user.Id,
                        code = code
                    }, HttpContext.Request.Scheme);
                    await _emailSender.SendEmailAsync(model.Email, "Confirm Email - Identity Manager",
                                        $"Please confirm Email by clicking here: <a href='{callbackurl}'>link</a>");
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return LocalRedirect(returnurl);
                }
                AddErrors(result);
            }

            model.RoleList = _roleManager.Roles.Select(x => x.Name).Select(i => new SelectListItem
            {
                Text = i,
                Value = i
            });
          
            return View(model);
        }
        [AllowAnonymous]
        public IActionResult Login(string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            return View();
        }
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
               
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password,model.RemberMe,lockoutOnFailure:true);
                if (result.Succeeded)
                {
                    var user = await _userManager.GetUserAsync(User);
                    var claims = await _userManager.GetClaimsAsync(user);
                    if (claims.Count > 0)
                    {
                        await _userManager.RemoveClaimAsync(user, claims.FirstOrDefault(u => u.Type == "FirstName"));
                        
                    }
                    await _userManager.AddClaimAsync(user, new Claim("FirstName", user.Name));
                    return LocalRedirect(returnurl);
                }
                if (result.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(VerfiyAuthenticatorCode), new { returnurl, model.RemberMe });
                    

                }
                if (result.IsLockedOut)
                {
                    return View("Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt");
                    return View(model);
                }
                    
            }
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> VerfiyAuthenticatorCode(bool remberMe, string returnUrl=null)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return View("Error");
            }
            ViewData["ReturnUrl"] = returnUrl;
            return View(new VerfiyAuthenticatorViewModel { ReturnUrl=returnUrl,RemberMe=remberMe});
        }


        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerfiyAuthenticatorCode(VerfiyAuthenticatorViewModel model)
        {
                model.ReturnUrl = model.ReturnUrl ?? Url.Content("~/");
                var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code,model.RemberMe,rememberClient: false);
                if (result.Succeeded)
                {
                    return LocalRedirect(model.ReturnUrl);
                }
                if (result.IsLockedOut)
                {
                    return View("Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt");
                    return View(model);
                }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LogOff()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        public async Task<IActionResult> RemoveAuthenticator()
        {
            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            await _userManager.SetTwoFactorEnabledAsync(user, false);
            return RedirectToAction(nameof(Index), "Home");
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string code,string userId)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    return View("Error");
                }
                var result = await _userManager.ConfirmEmailAsync(user,code);
                if (result.Succeeded)
                {
                    return View();
                }
                
            }
            return View("Error");
        }
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Lockout()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult NoAccess()
        {
            return View();
        }
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Error()
        {
            return View();
        }
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgetPassword()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public  async Task<IActionResult> ForgetPassword(ForgetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return RedirectToAction("ForgetPasswordConfirmation");
                }
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackurl = Url.Action("ResetPassword", "Account", new
                {
                    userid = user.Id,
                    code = code
                }, HttpContext.Request.Scheme
                );
                await _emailSender.SendEmailAsync(model.Email, "Reset Password - Identity Manager",
                                       $"Please reset your password by clicking here: <a href='{callbackurl}'>link</a>");
                return RedirectToAction(nameof(ForgetPasswordConfirmation));
            }
            return View(model);
        }
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null)
        {
            return code == null ? View("Error") : View();
        }
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public  async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user=await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return RedirectToAction(nameof(ResetPasswordConfirmation));
                }
                var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
                if (result.Succeeded)
                {
                    return RedirectToAction(nameof(ResetPasswordConfirmation));
                }
                AddErrors(result);
            }
            return View();
        }
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }


        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgetPasswordConfirmation()
        {
            return View();
        }
        [HttpGet]
        [AllowAnonymous]
        public IActionResult AuthenticatorConfirmation()
        {
            return View();
        }

        //[HttpPost]
        //[ValidateAntiForgeryToken]
        //public  async Task<IActionResult> ForgetPassword(ForgetPasswordViewModel model)
        //{
        //    return View(model);
        //}
        [HttpGet]
        [Authorize]
        public async Task<IActionResult> EnableAuthenticator()
        {
            string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            var token = await _userManager.GetAuthenticatorKeyAsync(user);
            string AuthUri = string.Format(AuthenticatorUriFormat, _urlEncoder.Encode("IdentityManager"),
                _urlEncoder.Encode(user.Email), token);

            var model = new TwoFactorAuthenticationViewModel() { Token = token, QRCodeUrl = AuthUri };
            
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EnableAuthenticator(TwoFactorAuthenticationViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                var succeeded = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
                if (succeeded)
                {
                    await _userManager.SetTwoFactorEnabledAsync(user, true);
                }
                else
                {
                    ModelState.AddModelError("Verifiy", "your two factor auth code could not be validated");
                    return View(model);
                }
                    return RedirectToAction(nameof(AuthenticatorConfirmation));
            }
            return View("Error");
        }
        private void AddErrors(IdentityResult result)
        {
            foreach(var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
    }
}
