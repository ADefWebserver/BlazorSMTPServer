using Azure.Data.Tables;
using Azure.Storage.Blobs;
using BlazorSMTPServer.Components;
using BlazorSMTPServer.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using Radzen;
using SMTPServerSvc.TestClient;
using System.Text.Json;

namespace BlazorSMTPServer;

public class Program
{
    public static async Task Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.AddServiceDefaults();

        builder.Configuration.AddUserSecrets<Program>(optional: true);

        // Add Azure Blob Service client from Aspire resource reference ("blobs")
        builder.AddAzureBlobServiceClient("blobs");
        // Add Azure Table Service client for settings storage 
        builder.AddAzureTableServiceClient("tables");

        // Add services to the container.
        builder.Services.AddRazorComponents()
            .AddInteractiveServerComponents();

        // Register email service
        builder.Services.AddScoped<BlobEmailService>();

        // Simple password gate middleware now uses appsettings.json value
        builder.Services.AddSingleton<AppPasswordValidator>();

        // Add required distributed cache for session + session services
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddSession(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.IsEssential = true; // required for non-consent scenarios
            options.IdleTimeout = TimeSpan.FromHours(8);
        });
        builder.Services.AddRadzenComponents();
        builder.Services.AddHttpContextAccessor();
        var app = builder.Build();

        // Ensure settings table contains current values from configuration (helps the Blazor UI read them)
        try
        {
            var tableClient = app.Services.GetRequiredService<TableServiceClient>();
            await EnsureSettingsTableAsync(tableClient, builder.Configuration, app.Services.GetRequiredService<ILogger<Program>>());
        }
        catch (Exception ex)
        {
            var logger = app.Services.GetService<ILogger<Program>>();
            logger?.LogWarning(ex, "Failed to ensure settings table at startup");
        }

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

    private static async Task EnsureSettingsTableAsync(TableServiceClient tableServiceClient, IConfiguration configuration, ILogger logger)
    {
        const string SettingsTableName = "SMTPSettings";
        const string PartitionKey = "SmtpServer";
        const string RowKey = "Current";

        try
        {
            logger.LogInformation("Ensuring settings table '{Table}' exists and is populated", SettingsTableName);
            var table = tableServiceClient.GetTableClient(SettingsTableName);
            await table.CreateIfNotExistsAsync();

            var ports = configuration.GetSection("SmtpServer:Ports").Get<int[]>() ?? Array.Empty<int>();
            var portsCsv = string.Join(", ", ports);
            var portsJson = JsonSerializer.Serialize(ports);

            var entity = new TableEntity(PartitionKey, RowKey)
            {
                { "ServerName", configuration["SmtpServer:ServerName"] ?? string.Empty },
                { "Ports", portsCsv },
                { "PortsJson", portsJson },
                { "AllowedRecipient", configuration["SmtpServer:AllowedRecipient"] ?? string.Empty },
                { "AllowedUsername", configuration["SmtpServer:AllowedUsername"] ?? string.Empty },
                { "AllowedPassword", configuration["SmtpServer:AllowedPassword"] ?? string.Empty },
                { "SpamhausKey", configuration["SmtpServer:SpamhausKey"] ?? string.Empty },
                { "EnableSpamFiltering", bool.TryParse(configuration["SmtpServer:EnableSpamFiltering"], out var esf) && esf },
                { "EnableSpfCheck", bool.TryParse(configuration["SmtpServer:EnableSpfCheck"], out var espf) && espf },
                { "EnableDmarcCheck", bool.TryParse(configuration["SmtpServer:EnableDmarcCheck"], out var edmarc) && edmarc },
                { "EnableDkimCheck", bool.TryParse(configuration["SmtpServer:EnableDkimCheck"], out var edkim) && edkim }
            };

            await table.UpsertEntityAsync(entity);
            logger.LogInformation("SMTP settings written to table '{Table}'", SettingsTableName);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to write SMTP settings to table");
        }
    }
}

public class AppPasswordValidator
{
    private readonly IConfiguration _configuration;

    public AppPasswordValidator(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public Task<string?> GetPasswordAsync()
    {
        // Read from configuration (User Secrets override appsettings in Development)
        var pwd = _configuration["AppPassword"];
        return Task.FromResult<string?>(pwd);
    }
}
