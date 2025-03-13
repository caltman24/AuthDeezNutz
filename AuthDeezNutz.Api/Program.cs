using System.Security.Claims;
using AuthDeezNutz.Api.Data;
using AuthDeezNutz.Api.Extensions;
using AuthDeezNutz.Api.Models;
using AuthDeezNutz.Api.Routes;
using AuthDeezNutz.Api.Services;
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
        policy.AllowAnyMethod();
        policy.AllowAnyHeader();
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
        opts.Password.RequiredLength = 8;
        opts.Password.RequireNonAlphanumeric = false;
    }).AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAuthServices(builder.Configuration);
builder.Services.AddAuthorizationBuilder()
    .AddDefaultPolicy("Default", pb =>
    {
        pb.RequireAuthenticatedUser();
        pb.RequireClaim(ClaimTypes.NameIdentifier);
        pb.Build();
    });
builder.Services.AddScoped<IAuthService, AuthService>();

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
    (HttpContext context) => { return Results.Ok(context.User.Claims.Select(c => new { c.Type, c.Value }).ToList()); }).RequireAuthorization();

app.MapAuthRoutes();

app.Run();
