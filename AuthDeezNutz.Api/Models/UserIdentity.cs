namespace AuthDeezNutz.Api.Models;

public class UserIdentity
{
    public int Id { get; set; }
    public string Provider { get; set; } // e.g. Google, Facebook, etc
    public string ProviderId { get; set; } // provider specific id (e.g. Google's sub, microsoft's oid)
    public string UserId { get; set; }
    public AppUser User { get; set; }
}