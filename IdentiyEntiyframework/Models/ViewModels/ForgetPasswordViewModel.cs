using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace IdentiyEntiyframework.Models.ViewModels
{
    public class ForgetPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        
    }
}
