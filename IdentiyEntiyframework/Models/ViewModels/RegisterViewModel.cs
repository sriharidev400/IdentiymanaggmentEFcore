using Microsoft.AspNetCore.Mvc.Rendering;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace IdentiyEntiyframework.Models.ViewModels
{
    public class RegisterViewModel
    {
        [Required]
        public string Name { get; set; }
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        [StringLength(100,ErrorMessage ="The {0} must be at least  {2} charcater long",MinimumLength =6)]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Display(Name="confirm password")]
        [Compare("Password",ErrorMessage ="The password and confirmation password do not match")]
        public string ConfirmPassword { get; set; }

        public IEnumerable<SelectListItem> RoleList { get; set; }
        public string? RoleSelected { get; set; }
    }
}
