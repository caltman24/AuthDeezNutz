using System.Security.Claims;
using System.Web;
using AuthDeezNutz.Api.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthDeezNutz.Api.Routes;

public static class Auth
{
    public static WebApplication MapAuthRoutes(this WebApplication app)
    {
        var authGroup = app.MapExternalAuthRoutes().MapGroup("/auth");

        // We pass in a redirect uri to a callback route on the remix app. The redirect after google auth provides the external cookie
        authGroup.MapGet("/login-external", ([FromQuery] string provider, [FromQuery] string redirectUri) =>
        Results.Challenge(
            new AuthenticationProperties
            {
                RedirectUri = redirectUri,
                // We Need to pass the provider name to the callback endpoint for ExternalLoginSignInAsync to work
                Items = { { "LoginProvider", provider } }
            }, [provider]));

        return app;
    }

    private static WebApplication MapExternalAuthRoutes(this WebApplication app)
    {
        var authGroup = app.MapGroup("/oauth");

        // After the remix app gets a response from the login with the external cookie, it will do a fetch request to this route with the external cookie
        // The external cookie is what contains the info from the external provider
        authGroup.MapGet("/callback", async (
            UserManager<AppUser> userManager,
            [FromServices] SignInManager<AppUser> signInManager) =>
        {
            var info = await signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return Results.BadRequest("Failed to get info from Google");
            }

            // set the authentication scheme to bearer
            signInManager.AuthenticationScheme = IdentityConstants.BearerScheme;

            // try to sign in the user with this external login provider if the user already exists
            // this method calls SignInAsync internally and signs outs out of external scheme
            var result =
                await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
            if (result.Succeeded)
            {
                return Results.Empty;
            }

            // user does not exist, create user
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (email == null)
            {
                return Results.BadRequest("Failed to get info from Google. Missing email.");
            }

            // email is the canonical identifier for the user
            var user = await userManager.FindByEmailAsync(email);
            if (user == null)
            {
                user = new AppUser
                {
                    Email = email,
                    UserName = email,
                    EmailConfirmed = true,
                    Role = "User"
                };

                await userManager.CreateAsync(user); // Add claims from external provider

                await userManager.AddClaimsAsync(user, [
                    new Claim("picture", info.Principal.FindFirstValue("picture") ?? ""),
                    new Claim(ClaimTypes.GivenName, info.Principal.FindFirstValue(ClaimTypes.GivenName) ?? ""),
                    new Claim(ClaimTypes.Surname, info.Principal.FindFirstValue(ClaimTypes.Surname) ?? "")
                ]);
            }

            //link the external login to the user
            await userManager.AddLoginAsync(user, info);
            await signInManager.SignInAsync(user, isPersistent: false);


            // SignInAsync handles returning the bearer tokens
            return Results.Empty;
        });

        return app;
    }
}

public record RefreshTokenModel(string AccessToken, string RefreshToken);