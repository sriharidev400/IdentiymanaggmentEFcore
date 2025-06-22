using IdentiyEntiyframework.DataBase;
using IdentiyEntiyframework.Services.IServices;

namespace IdentiyEntiyframework.Services
{
    public class NumberOfDaysForAccount : INumberOfDaysForAccount
    {
        private readonly ApplicationDBcontext _db;
        public NumberOfDaysForAccount(ApplicationDBcontext db)
        {
            _db = db;
        }
        public int Get(string userId)
        {
            var user = _db.Applicationusers.FirstOrDefault(u => u.Id == userId);
            if(user!=null &&user.DateCreated != DateTime.MinValue)
            {
                return (DateTime.Today - user.DateCreated).Days;
            }
            return 0;
        }
    }
}
