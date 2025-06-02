using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace IdentiyEntiyframework.Models.ViewModels
{
    public class LoginViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Display(Name ="Rember me?")]
        public bool RemberMe { get; set; }
    }
}
