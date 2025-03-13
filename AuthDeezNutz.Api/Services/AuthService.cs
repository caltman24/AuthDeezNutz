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

    public (string accessToken, string refreshToken) GenerateTokens(ClaimsPrincipal claimsPrincipal, string userId)
    {
        var claims = claimsPrincipal.Claims.ToList();

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

        return (accessTokenString, refreshToken);
    }

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

    public string GenerateRefreshToken()
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
    /// <returns></returns>
    public async Task<(string accessToken, string refreshToken)?> RevokeAndRefreshTokens(string accessToken)
    {
        var refreshToken = await _dbContext.RefreshTokens.FirstOrDefaultAsync(x => x.Token == accessToken);

        if (refreshToken == null || refreshToken.IsRevoked || refreshToken.Expires < DateTime.UtcNow)
        {
            return null;
        }

        var principal = ValidateAccessToken(accessToken);

        var userId = principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId == null) return null;

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return null;

        var (newAccessToken, newRefreshToken) = GenerateTokens(principal!, userId);

        refreshToken.IsRevoked = true;
        await _dbContext.RefreshTokens.AddAsync(
            new RefreshToken
            {
                Token = newRefreshToken,
                Created = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddDays(_configuration.GetValue<int>("Jwt:RefreshTokenLifetimeDays")),
                UserId = userId,
                IsRevoked = false
            });
        await _dbContext.SaveChangesAsync();

        return (newAccessToken, newRefreshToken);
    }
}

public interface IAuthService
{
    (string accessToken, string refreshToken) GenerateTokens(ClaimsPrincipal claimsPrincipal, string userId);
    Task<(string accessToken, string refreshToken)?> RevokeAndRefreshTokens(string accessToken);
    ClaimsPrincipal? ValidateAccessToken(string accessToken);
}