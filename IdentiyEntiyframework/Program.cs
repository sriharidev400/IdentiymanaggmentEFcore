using IdentiyEntiyframework;
using IdentiyEntiyframework.Authorize;
using IdentiyEntiyframework.DataBase;
using IdentiyEntiyframework.Models;
using IdentiyEntiyframework.Services;
using IdentiyEntiyframework.Services.IServices;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<ApplicationDBcontext>(Options =>
Options.UseSqlServer(builder.Configuration.GetConnectionString("conn")));

builder.Services.AddIdentity<Applicationuser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDBcontext>().AddDefaultTokenProviders();
builder.Services.AddTransient<IEmailSender, EmailSender>();
builder.Services.AddScoped<INumberOfDaysForAccount, NumberOfDaysForAccount>();
builder.Services.AddScoped<IAuthorizationHandler,AdminOver1000DaysHandler>();
builder.Services.ConfigureApplicationCookie(opt =>
{
    opt.AccessDeniedPath = new PathString("/Account/NoAccess");
});
builder.Services.Configure<IdentityOptions>(opt =>
{
    opt.Password.RequireDigit = false;
    opt.Password.RequireLowercase = false;
    opt.Password.RequireNonAlphanumeric = false;
    opt.Lockout.MaxFailedAccessAttempts = 3;
    //opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromDays(30);
    opt.SignIn.RequireConfirmedEmail = false;
});
builder.Services.AddAuthorization(opt =>
{
    opt.AddPolicy("Admin", policy => policy.RequireRole(SD.Admin));
    opt.AddPolicy("AdminAndUser", policy => policy.RequireRole(SD.Admin).RequireRole(SD.User));
    opt.AddPolicy("AdminRole_Createclaim", policy => policy.RequireRole(SD.Admin).RequireClaim("create","True"));
    opt.AddPolicy("Admin_Create_Edit_DeleteAccess", policy =>
    policy.RequireRole(SD.Admin)
    .RequireClaim("create", "True")
    .RequireClaim("edit", "True")
    .RequireClaim("delete", "True")
    );
opt.AddPolicy("Admin_Create_Edit_DeleteAccess_OR_SuperAdminRole", policy => policy.RequireAssertion(context => (
Admin_Create_Edit_DeleteAccess_OR_SuperAdminRole(context)
)));
    opt.AddPolicy("OnlySuperAdminChecker", p => p.Requirements.Add(new OnlySuperAdminChecker()));
    opt.AddPolicy("AdminwithMoreThan1000Days", p => p.Requirements.Add(new AdminwithMoreThan1000DaysRequirement(1000)));
});
var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

bool Admin_Create_Edit_DeleteAccess_OR_SuperAdminRole(AuthorizationHandlerContext context)
{
    return (
        context.User.IsInRole(SD.Admin) && context.User.HasClaim(c => c.Type == "Create" && c.Value == "True")
    && context.User.HasClaim(c => c.Type == "Edit" && c.Value == "True")
    && context.User.HasClaim(c => c.Type == "Delete" && c.Value == "True")
    )
    || context.User.IsInRole(SD.SuperAdmin);
        
}