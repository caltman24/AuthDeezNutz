using System.Security.Claims;
using AuthDeezNutz.Api.Data;
using AuthDeezNutz.Api.Models;
using AuthDeezNutz.Api.Routes;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

builder.Services.AddCors(opts =>
{
    opts.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins("http://localhost:5173", "https://client.scalar.com");
        policy.WithMethods("GET", "POST");
        policy.WithHeaders("Content-Type", "Cookie", "Accept");
    });
});

builder.Services.AddDbContext<AppDbContext>(opts =>
{
    opts.UseNpgsql(builder.Configuration.GetConnectionString("Default"));
});

builder.Services.AddIdentity<AppUser, IdentityRole>(opts =>
    {
        opts.User.RequireUniqueEmail = true;
        opts.Password.RequireDigit = true;
        opts.Password.RequireNonAlphanumeric = false;
    }).AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(opts =>
{
    opts.LoginPath = "/auth/login";
    opts.LogoutPath = "/auth/logout";

    opts.Events.OnRedirectToLogin = context =>
    {
        context.Response.StatusCode = 401;
        return Task.CompletedTask;
    };

    opts.Events.OnRedirectToAccessDenied = context =>
    {
        context.Response.StatusCode = 403;
        return Task.CompletedTask;
    };
});

builder.Services.AddAuthentication(opts =>
    {
        opts.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
        opts.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
        opts.DefaultSignInScheme = IdentityConstants.ExternalScheme;
    })
    .AddGoogle(opts =>
    {
        opts.ClientId = builder.Configuration["Google:ClientId"]!;
        opts.ClientSecret = builder.Configuration["Google:ClientSecret"]!;
        opts.CallbackPath = "/auth/google-cb";
        opts.SaveTokens = true;
        opts.ClaimActions.MapJsonKey("picture", "picture");
    });

builder.Services.AddAuthorizationBuilder()
    .AddDefaultPolicy("Default", pb =>
    {
        pb.RequireAuthenticatedUser();
        pb.AuthenticationSchemes = [IdentityConstants.ApplicationScheme];
        pb.Build();
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

// app.UseHttpsRedirection();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/",
        (HttpContext context) =>
        {
            return Results.Ok(context.User.Claims.Select(c => new { c.Type, c.Value }).ToList());
        })
    .RequireAuthorization();

app.MapAuthRoutes();

app.Run();