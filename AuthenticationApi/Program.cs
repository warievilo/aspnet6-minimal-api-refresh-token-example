using AuthenticationApi.Context;
using AuthenticationApi.Models.Request;
using AuthenticationApi.Models.Response;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MiniValidation;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JwtRegisteredClaimNames = System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames;


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<IConfiguration>(builder.Configuration);

builder.Services.AddDbContext<ApplicationDbContext>(
                x => x.UseSqlite(builder.Configuration.GetConnectionString("DefaultConn")));

builder.Services
    .AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,            
            ValidAudience = builder.Configuration["JWT:ValidAudience"],
            ValidIssuer = builder.Configuration["JWT:ValidIssuer"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Secret"]))
        };
    }
);

builder.Services.AddAuthorization();

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Refresh Token Example",
        Description = "For testing purposes",
        License = new OpenApiLicense 
        {
            Name = "MIT", 
            Url = new Uri("https://opensource.org/licenses/MIT") 
        }
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Insert your token JWT using this pattern: Bearer {your token}",
        Name = "Authorization",
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

#region Token Helpers

static async Task<string> GenerateAccessToken(
    UserManager<IdentityUser> userManager, 
    IConfiguration configuration, 
    string? email)
{
    var user = await userManager.FindByEmailAsync(email);
    var userRoles = await userManager.GetRolesAsync(user);
    var userClaims = await userManager.GetClaimsAsync(user);

    var identityClaims = new ClaimsIdentity();
    identityClaims.AddClaims(userClaims);
    identityClaims.AddClaims(userRoles.Select(s => new Claim("role", s)));
    identityClaims.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
    identityClaims.AddClaim(new Claim(JwtRegisteredClaimNames.Email, user.Email));
    identityClaims.AddClaim(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));

    var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]));
    var issuer = configuration["JWT:Issuer"];
    var audience = configuration["JWT:Audience"];
    var accessTokenExpirationTimeInMinutes = Int32.Parse(configuration["JWT:AccessTokenExpirationTimeInMinutes"]);

    var handler = new JwtSecurityTokenHandler();

    var securityToken = handler.CreateToken(new SecurityTokenDescriptor
    {
        Issuer = issuer,
        Audience = audience,
        SigningCredentials = new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256),
        Subject = identityClaims,
        NotBefore = DateTime.UtcNow,
        Expires = DateTime.UtcNow.AddMinutes(accessTokenExpirationTimeInMinutes),
        IssuedAt = DateTime.UtcNow,
        TokenType = "at+jwt"
    });

    var encodedJwt = handler.WriteToken(securityToken);

    return encodedJwt;
}

static async Task<string> GenerateRefreshToken(
    UserManager<IdentityUser> userManager, 
    IConfiguration configuration, 
    string? email)
{
    var identityClaims = new ClaimsIdentity();
    identityClaims.AddClaim(new Claim(JwtRegisteredClaimNames.Email, email));

    var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]));
    var issuer = configuration["JWT:Issuer"];
    var audience = configuration["JWT:Audience"];
    var refreshTokenExpirationTimeInDays = Int32.Parse(configuration["JWT:RefreshTokenExpirationTimeInDays"]);

    var handler = new JwtSecurityTokenHandler();

    var securityToken = handler.CreateToken(new SecurityTokenDescriptor
    {
        Issuer = issuer,
        Audience = audience,
        SigningCredentials = new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256),
        Subject = identityClaims,
        NotBefore = DateTime.Now,
        Expires = DateTime.Now.AddDays(refreshTokenExpirationTimeInDays),
        TokenType = "rt+jwt"
    });

    var encodedJwt = handler.WriteToken(securityToken);
    
    return encodedJwt;
}

static async Task<TokenValidationResult> ValidateRefreshToken(
    string? token, 
    IConfiguration configuration)
{
    var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]));
    var issuer = configuration["JWT:Issuer"];
    var audience = configuration["JWT:Audience"];

    var handler = new JsonWebTokenHandler();

    var result = handler.ValidateToken(token, new TokenValidationParameters()
    {
        RequireSignedTokens = false,
        ValidIssuer = issuer,
        ValidAudience = audience,
        IssuerSigningKey = authSigningKey
    });

    return result;
}

#endregion

#region Controller Methods

app.MapPost("/create-account", async (
    UserManager<IdentityUser> userManager, 
    UserRegisterRequest userRegisterRequest) =>
{
    if (!MiniValidator.TryValidate(userRegisterRequest, out var errors))
        return Results.ValidationProblem(errors);

    var user = new IdentityUser
    {
        UserName = userRegisterRequest.Email,
        Email = userRegisterRequest.Email,
        EmailConfirmed = true
    };

    var result = await userManager.CreateAsync(user, userRegisterRequest.Password);

    if (!result.Succeeded)
        return Results.BadRequest(result.Errors);

    return Results.Ok();
}).AllowAnonymous()
    .ProducesValidationProblem()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("Create Account")
    .WithTags("user");


app.MapPost("/sign-in", async (
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IConfiguration configuration,
        UserLoginRequest userLoginRequest) =>
{
    if (!MiniValidator.TryValidate(userLoginRequest, out var errors))
        return Results.ValidationProblem(errors);

    var result = await signInManager.PasswordSignInAsync(
                                        userLoginRequest.Email, 
                                        userLoginRequest.Password, 
                                        false, 
                                        true);

    if (result.IsLockedOut)
        return Results.BadRequest("Account blocked");

    if (!result.Succeeded)
        return Results.BadRequest("Invalid username or password");

    var accessToken = await GenerateAccessToken(userManager, configuration, userLoginRequest.Email);
    var refreshToken = await GenerateRefreshToken(userManager, configuration, userLoginRequest.Email);
    var accessTokenExpirationTimeInMinutes = Int32.Parse(configuration["JWT:AccessTokenExpirationTimeInMinutes"]);

    var userLoginResponse = new UserLoginResponse(
                                accessToken,
                                refreshToken,
                                accessTokenExpirationTimeInMinutes);

    return Results.Ok(userLoginResponse);
}).AllowAnonymous()
    .ProducesValidationProblem()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("Sign-in")
    .WithTags("user");


app.MapPost("/refresh-token", async (
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IConfiguration configuration,
        [FromForm] TokenRefreshRequest tokenRefreshRequest) =>
{
    if (!MiniValidator.TryValidate(tokenRefreshRequest, out var errors))
        return Results.ValidationProblem(errors);

    var result = await ValidateRefreshToken(tokenRefreshRequest.RefreshToken, configuration);

    if (!result.IsValid)
        return Results.BadRequest("Expired token");

    var user = await userManager.FindByEmailAsync(result.Claims[JwtRegisteredClaimNames.Email].ToString());
    
    if (user.LockoutEnabled)
        if (user.LockoutEnd < DateTime.Now)
            return Results.BadRequest("User blocked");

    var claims = await userManager.GetClaimsAsync(user);
    
    if (claims.Any(c => c.Type == "UserMustLoginAgain" && c.Value == "true"))
        return Results.BadRequest("User must login again");

    var accessToken = await GenerateAccessToken(userManager, configuration, result.Claims[JwtRegisteredClaimNames.Email].ToString());
    var refreshToken = await GenerateRefreshToken(userManager, configuration, result.Claims[JwtRegisteredClaimNames.Email].ToString());
    var accessTokenExpirationTimeInMinutes = Int32.Parse(configuration["JWT:AccessTokenExpirationTimeInMinutes"]);

    var userLoginResponse = new UserLoginResponse(
                                accessToken,
                                refreshToken,
                                accessTokenExpirationTimeInMinutes);

    return Results.Ok(userLoginResponse);
}).AllowAnonymous()
    .ProducesValidationProblem()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("Refresh Token")
    .WithTags("user");

app.MapGet("/protected-endpoint", (IHttpContextAccessor context) =>
{
    var claims = context.HttpContext?.User.Claims.Select(s => new { s.Type, s.Value });

    return Results.Ok(claims);
}).RequireAuthorization()
    .WithName("Protected Endpoint")
    .WithTags("user");

#endregion

app.Run();