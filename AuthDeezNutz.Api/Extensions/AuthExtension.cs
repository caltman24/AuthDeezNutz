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
        services.AddAuthentication(IdentityConstants.BearerScheme)
            .AddBearerToken(IdentityConstants.BearerScheme)
            .AddCookie(IdentityConstants.ExternalScheme, opts =>
            {
                opts.Cookie.Name = IdentityConstants.ExternalScheme;
                opts.ExpireTimeSpan = TimeSpan.FromMinutes(5);
            }) 
            .AddGoogle(opts =>
            {
                opts.ClientId = config["Google:ClientId"]!;
                opts.ClientSecret = config["Google:ClientSecret"]!;
                opts.CallbackPath = "/auth/google-cb";
                opts.SignInScheme = IdentityConstants.ExternalScheme;
                opts.ClaimActions.MapJsonKey("picture", "picture");
            });
    }
}