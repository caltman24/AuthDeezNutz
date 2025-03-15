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
using Microsoft.VisualBasic;

namespace AuthDeezNutz.Api.Routes;

public static class Auth
{
    public static WebApplication MapAuthRoutes(this WebApplication app)
    {
        var authGroup = app.MapExternalAuthRoutes().MapGroup("/auth");

        // Initiate the Oauth flow by redirecting to the provider authentication page
        // 1. The user authenticates with the provider directly
        // 2. Then the provider redirects back to the callback endpoint configured with the provider(not the app callback)
        // 3. Asp.Net middleware intercepts the callback request and processes the authentication
        // 4. After successful authentication, the user is redirected back to the app callback endpoint specified in the RedirectUri
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

        authGroup.MapGet("/logout", async (SignInManager<AppUser> signInManager) =>
        {
            await signInManager.SignOutAsync();
            return Results.Ok("Logged out successfully");
        }).RequireAuthorization();
        
        // get user claims
        authGroup.MapGet("/user", (HttpContext context) =>
        {
            return Results.Ok(context.User.Claims.Select(c => new { c.Type, c.Value }).ToList());
        }).RequireAuthorization();
        
        // Logout all sessions
        // To revoke specific sessions, we would have to write middleware to track sessions
        authGroup.MapPost("/revoke-sessions", async (
            HttpContext context,
            UserManager<AppUser> userManager,
            SignInManager<AppUser> signInManager) =>
        {
            var user = await userManager.GetUserAsync(context.User);
            if (user == null)
            {
                return Results.Unauthorized();
            }

            // Revoke all sessions for the user
            await userManager.UpdateSecurityStampAsync(user);
            
            await signInManager.SignOutAsync();
            
            return Results.Ok("Sessions revoked successfully");
        }).RequireAuthorization();

        return app;
    }

    private static WebApplication MapExternalAuthRoutes(this WebApplication app)
    {
        var authGroup = app.MapGroup("/oauth");

        // This callback handles creating/linking the user and signing in the user
        authGroup.MapGet("/callback", async (
            HttpContext context,
            UserManager<AppUser> userManager,
            [FromQuery] string returnUrl,
            SignInManager<AppUser> signInManager) =>
        {
            // this method calls context.AuthenticateAsync(IdentityConstants.ExternalScheme) internally
            var info = await signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return Results.BadRequest("Failed to get info from Google");
            }

            // Signs in a user via a previously registered third party login
            // This method calls SignOutAsync(IdentityConstants.ExternalScheme) internally if a provider is found
            var result = await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);
            if (result.Succeeded)
            {
                return Results.Redirect(returnUrl);
            }

            // create or link user account
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (string.IsNullOrEmpty(email))
            {
                return Results.BadRequest("Email is required");
            }

            // The email is used as the canonical identifier for the user across all providers including local
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
                var createResult = await userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                {
                    return Results.BadRequest("Failed to create user");
                }

                // Add claims from external provider
                await userManager.AddClaimsAsync(user, [
                    new Claim("picture", info.Principal.FindFirstValue("picture") ?? ""),
                    new Claim(ClaimTypes.GivenName, info.Principal.FindFirstValue(ClaimTypes.GivenName) ?? ""),
                    new Claim(ClaimTypes.Surname, info.Principal.FindFirstValue(ClaimTypes.Surname) ?? "")
                ]);
            }

            // link external provider
            await userManager.AddLoginAsync(user, info);
            
            // Sign out the external provider
            // use context.SignOut instead of signInManager.SignOut to explicitly sign out the external provider
            await context.SignOutAsync(IdentityConstants.ExternalScheme);
            
            // We could use ExternalLoginSignInAsync here, but we can avoid the unnecessary db call
            await signInManager.SignInAsync(user, true);
            
            return Results.Redirect(returnUrl);
        });

        return app;
    }
}