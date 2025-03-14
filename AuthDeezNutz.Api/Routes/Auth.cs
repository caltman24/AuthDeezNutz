using System.Security.Claims;
using System.Web;
using AuthDeezNutz.Api.Data;
using AuthDeezNutz.Api.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthDeezNutz.Api.Routes;

public static class Auth
{
    public static WebApplication MapAuthRoutes(this WebApplication app)
    {
        var authGroup = app.MapExternalAuthRoutes().MapGroup("/auth");

        // Remix app hits this login endpoint
        // Then, we redirect to the Google auth endpoint
        authGroup.MapGet("/login-external", ([FromQuery] string provider, [FromQuery] string returnUrl) =>
        Results.Challenge(
            new AuthenticationProperties
            {
                RedirectUri = $"/oauth/callback?returnUrl={HttpUtility.UrlEncode(returnUrl)}",
                Items = { { "LoginProvider", provider } }
            }, [provider]));

        // email password login
        authGroup.MapGet("/login", async (HttpContext context, [FromQuery] string returnUrl) =>
        {
            await context.SignInAsync(new ClaimsPrincipal(new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Name, "test"),
                new Claim(ClaimTypes.Role, "user")
            })), new AuthenticationProperties
            {
                IsPersistent = true,
                RedirectUri = returnUrl,
            });
        });

        authGroup.MapGet("/logout", async (HttpContext context,SignInManager<AppUser> signInManager) =>
        {
            await context.SignOutAsync(IdentityConstants.ApplicationScheme);
            await context.SignOutAsync(IdentityConstants.ExternalScheme);
            await context.SignOutAsync();
            await signInManager.SignOutAsync();
        }).RequireAuthorization();

        return app;
    }

    private static WebApplication MapExternalAuthRoutes(this WebApplication app)
    {
        var authGroup = app.MapGroup("/oauth");

        // After google authenticates, we redirect to this callback endpoint
        // This callback is responsible for generating the access token using the user info provided by Google before redirecting back to the Remix app
        // We redirect to the remix callback endpoint because the Remix app needs to set the access token in the cookie
        authGroup.MapGet("/callback", async (
            HttpContext context,
            AppDbContext dbContext,
            UserManager<AppUser> userManager,
            [FromQuery] string returnUrl,
            [FromServices] SignInManager<AppUser> signInManager) =>
        {
            var info = await signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return Results.BadRequest("Failed to get info from Google");
            }

            var picture = info.Principal.FindFirstValue("picture");
            var givenName = info.Principal.FindFirstValue(ClaimTypes.GivenName);
            var surname = info.Principal.FindFirstValue(ClaimTypes.Surname);

            // try to sign in the user with this external login provider if the user already exists
            var result =
                await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);
            
            if (result.Succeeded)
            {
                return Results.Redirect(returnUrl);
            }

            // user does not exist, create user
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (email == null)
            {
                return Results.BadRequest("Failed to get info from Google. Missing email.");
            }

            var user = await userManager.FindByEmailAsync(email);
            if (user == null)
            {
                // Create new user
                user = new AppUser
                {
                    Email = email,
                    UserName = email,
                    EmailConfirmed = true,
                    Role = "User"
                };
                // add user to db
                await userManager.CreateAsync(user);

                await userManager.AddClaimsAsync(user, [
                    new Claim("picture", picture ?? ""),
                    new Claim(ClaimTypes.GivenName, givenName ?? ""),
                    new Claim(ClaimTypes.Surname, surname ?? "")
                ]);
            }

            // link the external login to the user
            await userManager.AddLoginAsync(user, info);
            await signInManager.SignInAsync(user, isPersistent: true);

            await dbContext.SaveChangesAsync();

            return Results.Redirect(returnUrl);
        });

        return app;
    }
}