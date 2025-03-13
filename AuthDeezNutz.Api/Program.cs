using System.Security.Claims;
using AuthDeezNutz.Api.Data;
using AuthDeezNutz.Api.Models;
using AuthDeezNutz.Api.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddResponseCaching();

builder.Services.AddOpenApi();

builder.Services.AddCors(opts =>
{
    opts.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins("http://localhost:5173", "https://client.scalar.com");
        policy.AllowAnyMethod();
        policy.AllowAnyHeader();
        policy.AllowCredentials();
    });
});

builder.Services.AddDbContext<AppDbContext>(opts =>
{
    opts.UseNpgsql(builder.Configuration.GetConnectionString("Default"));
});

builder.Services.AddIdentityCore<AppUser>(opts =>
    {
        opts.User.RequireUniqueEmail = true;
        opts.Password.RequireDigit = true;
        opts.Password.RequiredLength = 8;
        opts.Password.RequireNonAlphanumeric = false;
    }).AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAuthentication(opts =>
    {
        opts.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        opts.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
        opts.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    }).AddJwtBearer(opts =>
    {
        opts.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Convert.FromBase64String(builder.Configuration["Jwt:Key"]))
        };
    })
    .AddGoogle(opts =>
    {
        opts.ClientId = builder.Configuration["Google:ClientId"];
        opts.ClientSecret = builder.Configuration["Google:ClientSecret"];
        opts.CallbackPath = "/oauth/google-cb";
        opts.SignInScheme = "external_temp";
        opts.ClaimActions.MapJsonKey("urn:google:picture", "picture");
    })
    .AddCookie("external_temp", opts =>
    {
        // This cookie is used to store the oath state after the user has authenticated with Google.
        // It is not used for anything else.
        // It is needed in order to store the state of the authentication process after the user has authenticated with Google.
        opts.Cookie.Name = "external_temp";
        opts.ExpireTimeSpan = TimeSpan.FromMinutes(5);
        opts.SlidingExpiration = false;
    });

builder.Services.AddAuthorizationBuilder();
builder.Services.AddScoped<IAuthService, AuthService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

// app.UseHttpsRedirection();
app.UseResponseCaching();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/",
    (HttpContext context) => { return Results.Ok(context.User.Claims.Select(c => new { c.Type, c.Value }).ToList()); });


var authGroup = app.MapGroup("/auth");


// Remix app hits this login endpoint
// Then, we redirect to the Google auth endpoint
authGroup.MapGet("/login", (HttpContext context) =>
{
    return Results.Challenge(new AuthenticationProperties
    {
        RedirectUri = "/auth/google-cb",
        Items = { { "returnUrl", "http://localhost:5173" } }
    }, [GoogleDefaults.AuthenticationScheme]);
});

// After google authenticates, we redirect to this callback endpoint
// This callback is responsible for generating the access token using the user info provided by Google before redirecting back to the Remix app
// We redirect to the remix callback endpoint because the Remix app needs to set the access token in the cookie
authGroup.MapGet("/google-cb",
    async (HttpContext context, IAuthService authService, AppDbContext dbContext, IConfiguration configuration,
        UserManager<AppUser> userManager) =>
    {
        var result = await context.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);
        if (!result.Succeeded)
            return Results.BadRequest("Google Authentication failed");

        // Sign out the temporary cookie. Optional.
        await context.SignOutAsync("external_temp");

        var userClaims = result.Principal;
        var providerId = userClaims.FindFirstValue(ClaimTypes.NameIdentifier);
        var email = userClaims.FindFirstValue(ClaimTypes.Email);

        if (string.IsNullOrEmpty(providerId) || string.IsNullOrEmpty(email))
        {
            return Results.BadRequest("Missing providerId or email");
        }

        // check if user exists by email
        var user = await userManager.FindByEmailAsync(email);

        if (user == null)
        {
            // Create new user
            user = new AppUser
            {
                Email = email,
                EmailConfirmed = true,
                Role = "User"
            };
            
            user.Identities.Add(new UserIdentity
            {
                Provider = "Google",
                ProviderId = providerId,
            });
            
            // add user to db
            await userManager.CreateAsync(user);
            await dbContext.SaveChangesAsync();
        }
        else
        {
            // existing user, check if provider is linked
            var identity = user.Identities.FirstOrDefault(x => x.Provider == "Google");
            if (identity == null)
            {
                // link provider
                user.Identities.Add(new UserIdentity
                {
                    Provider = "Google",
                    ProviderId = providerId,
                });
            }
            // Update provider-specific ID if it changed (optional)
            else if (identity.ProviderId != providerId)
            {
                // provider id mismatch
                identity.ProviderId = providerId;
            }
        }
        
        // generate access token 
        var (accessToken, refreshToken) = authService.GenerateTokens(userClaims, providerId);
        await dbContext.RefreshTokens.AddAsync(new RefreshToken
        {
            Token = refreshToken,
            Created = DateTime.UtcNow,
            Expires = DateTime.UtcNow.AddDays(configuration.GetValue<int>("Jwt:RefreshTokenLifetimeDays")),
            UserId = providerId,
            IsRevoked = false
        });
        await dbContext.SaveChangesAsync();

        var returnUrl = result.Properties.Items["returnUrl"] ?? "http://localhost:5173";
        return Results.Redirect($"{returnUrl}/auth-cb?access_token={accessToken}&refresh_token={refreshToken}");
    });

authGroup.MapPost("/refresh",
    (HttpContext context, RefreshTokenModel refreshTokenModel) => { return Results.Ok("refresh"); });

authGroup.MapGet("/logout", (HttpContext context) =>
{
    context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/");
});


app.Run();

public record RefreshTokenModel(string AccessToken, string RefreshToken);