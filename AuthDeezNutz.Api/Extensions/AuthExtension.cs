using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace AuthDeezNutz.Api.Extensions;

public static class AuthExtension
{
    public static void AddAuthServices(this IServiceCollection services, IConfiguration config)
    {
        services.AddAuthentication(opts =>
            {
                opts.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                opts.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                opts.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(opts =>
            {
                opts.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = config["Jwt:Issuer"],
                    ValidAudience = config["Jwt:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(config["Jwt:Key"]!))
                };
            })
            .AddGoogle(opts =>
            {
                opts.ClientId = config["Google:ClientId"]!;
                opts.ClientSecret = config["Google:ClientSecret"]!;
                opts.CallbackPath = "/oauth/google-cb";
                opts.SignInScheme = IdentityConstants.ExternalScheme;
                opts.ClaimActions.MapJsonKey(ClaimTypes.Uri, "picture");
            });
    }
}