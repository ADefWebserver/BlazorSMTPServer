using BlazorSMTPServer.Components;
using SMTPServerSvc.TestClient;
using Azure.Storage.Blobs;
using BlazorSMTPServer.Services;
using Azure.Data.Tables;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace BlazorSMTPServer;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.AddServiceDefaults();

        // Add Azure Blob Service client from Aspire resource reference ("blobs")
        builder.AddAzureBlobServiceClient("blobs");
        // Add Azure Table Service client for settings and password storage
        builder.AddAzureTableServiceClient("tables");

        // Add services to the container.
        builder.Services.AddRazorComponents()
            .AddInteractiveServerComponents();

        // Register email service
        builder.Services.AddScoped<BlobEmailService>();

        // Simple password gate middleware using table storage value (table: SMPTSettings pk:SmtpServer rk:AppPassword)
        builder.Services.AddSingleton<AppPasswordValidator>();

        // Add required distributed cache for session + session services
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddSession(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.IsEssential = true; // required for non-consent scenarios
            options.IdleTimeout = TimeSpan.FromHours(8);
        });

        var app = builder.Build();

        app.MapDefaultEndpoints();

        // needed for session usage
        app.UseSession();

        // Password gate (runs early, static files allowed, settings page allowed only if authenticated) - skip if no password set
        app.Use(async (context, next) =>
        {
            if (context.Request.Path.StartsWithSegments("/static") || context.Request.Path == "/favicon.png")
            {
                await next();
                return;
            }
            // allow unauth to attempt login if password exists
            var validator = context.RequestServices.GetRequiredService<AppPasswordValidator>();
            var pwd = await validator.GetPasswordAsync();
            if (string.IsNullOrEmpty(pwd))
            {
                await next();
                return; // open access
            }
            // check session
            if (context.Session.GetString("app_pwd_ok") == "1")
            {
                await next();
                return;
            }
            if (context.Request.Path == "/login" && context.Request.Method == "POST")
            {
                var form = await context.Request.ReadFormAsync();
                var entered = form["password"].ToString();
                if (!string.IsNullOrEmpty(entered) && entered == pwd)
                {
                    context.Session.SetString("app_pwd_ok", "1");
                    context.Response.Redirect("/");
                    return;
                }
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("Invalid password");
                return;
            }
            if (context.Request.Path == "/login")
            {
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync("<html><body><form method='post'><h3>Enter Access Password</h3><input type='password' name='password'/><button>Login</button></form></body></html>");
                return;
            }
            // redirect to login
            context.Response.Redirect("/login");
        });

        // Add SMTP test endpoint for development
        app.MapGet("/test-smtp", async () =>
        {
            try
            {
                await SmtpTestClient.TestSmtpServer();
                return Results.Ok("SMTP tests completed successfully. Check console output for details.");
            }
            catch (Exception ex)
            {
                return Results.Problem($"SMTP test failed: {ex.Message}");
            }
        });

        // Configure the HTTP request pipeline.
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }

        app.UseHttpsRedirection();

        app.UseAntiforgery();

        app.MapStaticAssets();
        app.MapRazorComponents<App>()
            .AddInteractiveServerRenderMode();

        app.Run();
    }
}

public class AppPasswordValidator
{
    private readonly TableServiceClient _tableServiceClient;
    private const string TableName = "SMPTSettings";
    private const string PartitionKey = "SmtpServer";
    private const string RowKey = "AppPassword";
    private string? _cached;
    private DateTime _cachedAt;
    private readonly TimeSpan _cacheDuration = TimeSpan.FromMinutes(2);

    public AppPasswordValidator(TableServiceClient tableServiceClient)
    {
        _tableServiceClient = tableServiceClient;
    }

    public async Task<string?> GetPasswordAsync()
    {
        if (_cached != null && DateTime.UtcNow - _cachedAt < _cacheDuration)
            return _cached;
        try
        {
            var table = _tableServiceClient.GetTableClient(TableName);
            await table.CreateIfNotExistsAsync();
            var entity = await table.GetEntityIfExistsAsync<TableEntity>(PartitionKey, RowKey);
            _cached = entity.HasValue ? entity.Value.GetString("Password") : null;
            _cachedAt = DateTime.UtcNow;
            return _cached;
        }
        catch
        {
            return null; // treat as open access if problem
        }
    }
}
