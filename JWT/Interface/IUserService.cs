using JWT.Entities;

namespace JWT.Interface
{
    public interface IUserService
    {
        User? Add(User newUser);
        User? Get(string userName);
    }
}
