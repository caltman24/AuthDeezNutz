namespace AuthDeezNutz.Api.Models;

public class RefreshToken
{
    public string Token { get; set; }
    public DateTime Created { get; set; }
    public DateTime Expires { get; set; }
    public bool IsRevoked { get; set; }
    public string UserId { get; set; }
    // public string UserId { get; set; }
}