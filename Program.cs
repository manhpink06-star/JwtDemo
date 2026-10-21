using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Khóa bí mật ký JWT (phải >= 32 ký tự)
const string SecretKey = "ChuoiBiMatRatDaiItNhat32KyTu_CMCU_2026!";
const string Issuer = "JwtDemoServer";
const string Audience = "JwtDemoClient";

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = Issuer,
            ValidAudience = Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey))
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseDefaultFiles();   // tự mở wwwroot/index.html
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

// Danh sách tài khoản giả lập
var users = new List<AppUser>
{
    new("admin", "123456", "admin"),
    new("user",  "123456", "user")
};

// 1) Đăng nhập -> server xác thực và trả JWT (*)
app.MapPost("/api/login", (LoginRequest req) =>
{
    var u = users.FirstOrDefault(x => x.Username == req.Username && x.Password == req.Password);
    if (u is null) return Results.Unauthorized();

    var claims = new[]
    {
        new Claim(ClaimTypes.Name, u.Username),
        new Claim(ClaimTypes.Role, u.Role)
    };
    var creds = new SigningCredentials(
        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey)),
        SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
        issuer: Issuer, audience: Audience, claims: claims,
        expires: DateTime.UtcNow.AddMinutes(30), signingCredentials: creds);

    return Results.Ok(new
    {
        token = new JwtSecurityTokenHandler().WriteToken(token),
        role = u.Role
    });
});

// 2) API cho user và admin
app.MapGet("/api/user-data", (ClaimsPrincipal me) =>
        Results.Ok(new { message = $"Xin chào {me.Identity!.Name}, bạn được truy cập chức năng USER" }))
   .RequireAuthorization(p => p.RequireRole("user", "admin"));

// 3) API chỉ dành cho admin
app.MapGet("/api/admin-data", (ClaimsPrincipal me) =>
        Results.Ok(new { message = $"Xin chào {me.Identity!.Name}, bạn được truy cập chức năng ADMIN" }))
   .RequireAuthorization(p => p.RequireRole("admin"));

app.Run();

record LoginRequest(string Username, string Password);
record AppUser(string Username, string Password, string Role);