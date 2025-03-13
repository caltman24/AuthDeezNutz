using System.Security.Claims;
using System.Web;
using AuthDeezNutz.Api.Data;
using AuthDeezNutz.Api.Models;
using AuthDeezNutz.Api.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
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
        authGroup.MapGet("/login", ([FromQuery] string provider, [FromQuery] string returnUrl) => Results.Challenge(
            new AuthenticationProperties
            {
                RedirectUri = $"/oauth/callback?returnUrl={HttpUtility.UrlEncode(returnUrl)}",
                Items = { { "LoginProvider", provider } }
            }, [provider]));

        authGroup.MapPost("/refresh",
            async (RefreshTokenModel refreshTokenModel,
                IAuthService authService) =>
            {
                var res = await authService.RevokeAndRefreshTokens(refreshTokenModel.AccessToken,
                    refreshTokenModel.RefreshToken);

                return res == null
                    ? Results.Unauthorized()
                    : Results.Ok(new { res.Value.accessToken, res.Value.refreshToken });
            }).RequireAuthorization();

        authGroup.MapGet("/logout", async (HttpContext context, IAuthService authService) =>
        {
            var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            
            if (userId != null)
            {
                await authService.RevokeAllUserRefreshTokens(userId);
            }
            
            await context.SignOutAsync();
            return Results.Redirect("/");
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
            IAuthService authService,
            AppDbContext dbContext,
            IConfiguration configuration,
            UserManager<AppUser> userManager,
            [FromQuery] string returnUrl,
            [FromServices] SignInManager<AppUser> signInManager) =>
        {
            var info = await signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return Results.BadRequest("Failed to get info from Google");
            }

            // try to sign in the user with this external login provider if the user already exists
            var result =
                await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
            if (result.Succeeded)
            {
                // user is already linked, generate access token 
                var existingUser = await userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
                if (existingUser == null)
                {
                    return Results.BadRequest("Failed to get existing user");
                }

                var (aToken, rToken) = await authService.GenerateTokensAsync(existingUser, ["user"], info.Principal);
                return Results.Redirect(
                    $"{returnUrl}?access_token={HttpUtility.UrlEncode(aToken)}&refresh_token={HttpUtility.UrlEncode(rToken)}");
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
            }

            //link the external login to the user
            await userManager.AddLoginAsync(user, info);
            await signInManager.SignInAsync(user, isPersistent: false);

            // generate access token 
            var (accessToken, refreshToken) = await authService.GenerateTokensAsync(user, ["user"], info.Principal);
            await dbContext.RefreshTokens.AddAsync(new RefreshToken
            {
                Token = refreshToken,
                Created = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddDays(configuration.GetValue<int>("Jwt:RefreshTokenLifetimeDays")),
                UserId = user.Id,
                IsRevoked = false
            });
            await dbContext.SaveChangesAsync();

            return Results.Redirect(
                $"{returnUrl}?access_token={HttpUtility.UrlEncode(accessToken)}&refresh_token={HttpUtility.UrlEncode(refreshToken)}");
        });

        return app;
    }
}

public record RefreshTokenModel(string AccessToken, string RefreshToken);