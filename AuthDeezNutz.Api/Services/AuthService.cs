using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthDeezNutz.Api.Data;
using AuthDeezNutz.Api.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace AuthDeezNutz.Api.Services;

public class AuthService : IAuthService
{
    private readonly IConfiguration _configuration;
    private readonly AppDbContext _dbContext;
    private readonly UserManager<AppUser> _userManager;

    public AuthService(IConfiguration configuration, AppDbContext dbContext, UserManager<AppUser> userManager)
    {
        _configuration = configuration;
        _dbContext = dbContext;
        _userManager = userManager;
    }


    /// <summary>
    /// Generates an access token and refresh token. Handles database operations.
    /// </summary>
    /// <param name="user"></param>
    /// <param name="roles"></param>
    /// <param name="claimsPrincipal"></param>
    /// <returns></returns>
    public async Task<(string accessToken, string refreshToken)> GenerateTokensAsync(AppUser user, List<string> roles,
        ClaimsPrincipal? claimsPrincipal = null)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

        if (claimsPrincipal != null)
        {
            var name = claimsPrincipal.FindFirstValue(ClaimTypes.Name);
            var picture = claimsPrincipal.FindFirstValue(ClaimTypes.Uri);
            claims.Add(new Claim(JwtRegisteredClaimNames.Name, name ?? ""));
            claims.Add(new Claim(JwtRegisteredClaimNames.Picture, picture ?? ""));
        }

        claims.AddRange(roles.Select(role => new Claim("role", role)));

        // Access Token
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var accessToken = new JwtSecurityToken(
            _configuration["Jwt:Issuer"],
            _configuration["Jwt:Audience"],
            claims,
            expires: DateTime.UtcNow.AddMinutes(_configuration.GetValue<int>("Jwt:AccessTokenLifetimeMinutes")),
            signingCredentials: credentials
        );
        var accessTokenString = new JwtSecurityTokenHandler().WriteToken(accessToken);
        var refreshToken = GenerateRefreshToken();

        // add new refresh token to db
        await _dbContext.RefreshTokens.AddAsync(new RefreshToken
        {
            Token = refreshToken,
            Created = DateTime.UtcNow,
            Expires = DateTime.UtcNow.AddDays(_configuration.GetValue<int>("Jwt:RefreshTokenLifetimeDays")),
            UserId = user.Id,
            IsRevoked = false
        });
        await _dbContext.SaveChangesAsync();

        return (accessTokenString, refreshToken);
    }

    /// <summary>
    /// Validates an access token.
    /// </summary>
    /// <param name="accessToken">Access token to validate.</param>
    /// <returns>Returns null if invalid.</returns>
    public ClaimsPrincipal? ValidateAccessToken(string accessToken)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]);

        var principal = tokenHandler.ValidateToken(accessToken, new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _configuration["Jwt:Issuer"],
            ValidAudience = _configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(key)
        }, out _);

        return principal;
    }

    /// <summary>
    /// Generates a 64 byte refresh token
    /// </summary>
    /// <returns></returns>
    private static string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    /// <summary>
    /// Used on refresh token endpoint. Revokes the old refresh token and generates a new access and refresh token. If the
    /// refresh token is invalid or expired or the access token is invalid, returns null. Handles database operations.
    /// </summary>
    /// <param name="accessToken"></param>
    /// <param name="refreshToken"></param>
    /// <returns>Returns null if invalid or expired</returns>
    public async Task<(string accessToken, string refreshToken)?> RevokeAndRefreshTokens(string accessToken,
        string refreshToken)
    {
        var oldToken = await _dbContext.RefreshTokens.FirstOrDefaultAsync(x => x.Token == refreshToken);

        if (oldToken == null || oldToken.IsRevoked || oldToken.Expires < DateTime.UtcNow)
        {
            return null;
        }

        var principal = ValidateAccessToken(accessToken);

        var userId = principal?.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null) return null;

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return null;

        var roles = await _userManager.GetRolesAsync(user);

        oldToken.IsRevoked = true;

        var (newAccessToken, newRefreshToken) = await GenerateTokensAsync(user, roles.ToList(), principal);

        return (newAccessToken, newRefreshToken);
    }

    public async Task RevokeAllUserRefreshTokens(string userId)
    {
        // Revoke all refresh tokens for this user
        var userTokens = await _dbContext.RefreshTokens
            .Where(t => t.UserId == userId && !t.IsRevoked)
            .ToListAsync();

        foreach (var token in userTokens)
        {
            token.IsRevoked = true;
        }

        await _dbContext.SaveChangesAsync();
    }
}

public interface IAuthService
{
    Task<(string accessToken, string refreshToken)> GenerateTokensAsync(AppUser user, List<string> roles,
        ClaimsPrincipal? claims = null);

    Task<(string accessToken, string refreshToken)?> RevokeAndRefreshTokens(string accessToken, string refreshToken);
    Task RevokeAllUserRefreshTokens(string userId);
}