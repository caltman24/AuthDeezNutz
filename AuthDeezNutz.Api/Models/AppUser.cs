﻿using Microsoft.AspNetCore.Identity;

namespace AuthDeezNutz.Api.Models;

public class AppUser : IdentityUser
{
    public string Role { get; set; }
}