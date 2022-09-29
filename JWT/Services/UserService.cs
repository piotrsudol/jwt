using JWT.Entities;
using JWT.Interface;

namespace JWT.Services
{
    public class UserService : IUserService
    {
        private List<User> users = new List<User>();

        public User? Add(User newUser)
        {
            if (Get(newUser.UserName) != null)
                return null;

            users.Add(newUser);
            return newUser;
        }
        public User? Get(string userName) => users.Find(u => u.UserName == userName);
    }
}
