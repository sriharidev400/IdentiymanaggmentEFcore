using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace IdentiyEntiyframework.Models
{
    public class Applicationuser:IdentityUser
    {
        [Required]
        public string Name { get; set; }
    }
}
