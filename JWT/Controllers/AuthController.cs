using JWT.Entities;
using JWT.Interface;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly IConfiguration configuration;
        private readonly IUserService userService;

        public AuthController(IConfiguration configuration, IUserService userService)
        {
            this.configuration = configuration;
            this.userService = userService;
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] salt);

            User user = new() { UserName = request.UserName, PasswordHash = passwordHash, PasswordSalt = salt };
            var addedUser = userService.Add(user);

            return addedUser == null ? BadRequest("User already exist") : Ok(addedUser);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            var user = userService.Get(request.UserName);

            if (user == null )
                return BadRequest("User not found");

            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
                return BadRequest("Wrong password.");

            string token = CreateToken(user);

            return Ok(token);
        }

        private string CreateToken(User user)
        {

            List<Claim> claims = new List<Claim> { new Claim(ClaimTypes.Name, user.UserName) };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(configuration.GetSection("AppSettings:Token").Value));

            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: credentials
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] salt)
        {
            using (var hmac = new HMACSHA512())
            {
                salt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }
    }
}
