using AuthDeezNutz.Api.Data;
using AuthDeezNutz.Api.Models;
using AuthDeezNutz.Api.Routes;
using Microsoft.AspNetCore.Authentication;
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
        policy.AllowAnyHeader();
        policy.AllowCredentials();
    });
});

builder.Services.AddDbContext<AppDbContext>(opts =>
{
    opts.UseNpgsql(builder.Configuration.GetConnectionString("Default"));
});

// Check the AddIdentity definition to see what is added by default
builder.Services.AddIdentity<AppUser, IdentityRole>(opts =>
    {
        opts.User.RequireUniqueEmail = true;
        opts.Password.RequireDigit = true;
        opts.Password.RequireNonAlphanumeric = false;
    }).AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

// Configure the Application Cookie from Identity
// Can also configure the external cookie if needed
builder.Services.ConfigureApplicationCookie(opts =>
{
    opts.Cookie.Name = "auth";
    opts.LoginPath = "/auth/login";
    opts.LogoutPath = "/auth/logout";

    // Since a js client is used, we need to override the default redirect behavior and return a 401 or 403
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

builder.Services.AddAuthentication()
    .AddGoogle(opts =>
    {
        opts.ClientId = builder.Configuration["Google:ClientId"]!;
        opts.ClientSecret = builder.Configuration["Google:ClientSecret"]!;
        opts.CallbackPath = "/auth/google-cb";
        
        // .net doesn't map the picture claim by default
        // ClaimTypes doesn't have a picture claim type
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