using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace IdentiyEntiyframework.Models.ViewModels
{
    public class TwoFactorAuthenticationViewModel
    {
        
        public string Code { get; set; }
        public string? Token { get; set; }

        public string? QRCodeUrl { get; set; }

    }
}
