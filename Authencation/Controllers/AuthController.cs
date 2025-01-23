using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _configuration;

    public AuthController(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginModel model)
    {
        // Check credentials (this should be done against a user store, e.g., database)
        if (model.Username == "test" && model.Password == "password")
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, model.Username),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: creds
            );

            return Ok( new JwtSecurityTokenHandler().WriteToken(token));
        }

        return Unauthorized();
    }
    [Authorize(Roles = "SuperAdmin")]
    [HttpGet("GetSuperAdminData")]
    public IActionResult GetAdminData()
    {
        return Ok("This is SuperAdmin data.");
    }
    [Authorize(Roles ="Admin")]
    [HttpGet("GetAdminData")]
    public IActionResult GetSimpleUserData()
    {
        return Ok("This is Admin data.");
    }

}

public class LoginModel
{
    public string Username { get; set; }
    public string Password { get; set; }
}
