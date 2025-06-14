using NuGet.Protocol.Core.Types;

namespace IdentiyEntiyframework.Models.ViewModels
{
    public class RolesViewModel
    {
        public RolesViewModel()
        {
            RolesList = [];
        }
        public Applicationuser User { get; set; }
        public List<RoleSelection> RolesList { get; set; }
    }
    public class RoleSelection
    {
        public string RoleName { get; set; }
        public bool IsSelected { get; set; }
    }
}
