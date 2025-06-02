using IdentiyEntiyframework.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentiyEntiyframework.DataBase
{
    public class ApplicationDBcontext: IdentityDbContext
    {
        public ApplicationDBcontext(DbContextOptions Options)
            :base(Options)
        {
            
        }
        public DbSet<Applicationuser> Applicationusers { get; set; }

    }
}
