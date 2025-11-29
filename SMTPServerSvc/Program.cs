using Azure.Storage.Blobs;
using Azure.Data.Tables;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SmtpServer.Storage;
using SmtpServer.Authentication;
using SMTPServerSvc.Configuration;
using SMTPServerSvc.Services;
using System.Collections;
using System.Linq;
using System.Text.Json;

namespace SMTPServerSvc;

internal class Program
{
    static async Task Main(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);
        builder.AddServiceDefaults();

        builder.Configuration.AddUserSecrets<Program>(optional: true);

        // Add Azure clients from Aspire resource references (names must match AppHost: blobs, tables)
        builder.AddAzureBlobServiceClient("blobs");
        builder.AddAzureTableServiceClient("tables");

        // Load settings from appsettings.json (SmtpServer section)
        var smtpConfig =
            builder.Configuration.GetSection(SmtpServerConfiguration.SectionName)
            .Get<SmtpServerConfiguration>()
            ?? new SmtpServerConfiguration();

        // Minimal validation
        if (smtpConfig.Ports is null || smtpConfig.Ports.Length == 0 || string.IsNullOrWhiteSpace(smtpConfig.ServerName))
        {
            var tempLoggerFactory = LoggerFactory.Create(lb => lb.AddConsole());
            var tempLogger = tempLoggerFactory.CreateLogger<Program>();
            tempLogger.LogError("SMTP settings incomplete in appsettings.json. Required settings are missing. Service will stop.");
            return;
        }

        // Register configuration instance
        builder.Services.AddSingleton(smtpConfig);

        // DNS Resolver service
        builder.Services.AddSingleton<IDnsResolver, DnsResolver>();
        // DnsClient LookupClient
        builder.Services.AddSingleton<DnsClient.ILookupClient, DnsClient.LookupClient>();
        // Mail authentication service
        builder.Services.AddSingleton<MailAuthenticationService>();

        // Custom logger provider (table name comes from config)
        builder.Services.AddSingleton<TableStorageLoggerProvider>(sp =>
        {
            var tableSvcClient = sp.GetRequiredService<TableServiceClient>();
            var cfg = sp.GetRequiredService<SmtpServerConfiguration>();
            return new TableStorageLoggerProvider(tableSvcClient, "SMTPServerLogs");
        });

        // Register MemoryCache for spam check caching
        builder.Services.AddMemoryCache();

        // SMTP components
        builder.Services.AddSingleton<DefaultMessageStore>();
        builder.Services.AddSingleton<IMessageStore>(sp => sp.GetRequiredService<DefaultMessageStore>());
        builder.Services.AddSingleton<DefaultMailboxFilter>();
        builder.Services.AddSingleton<IMailboxFilter>(sp => sp.GetRequiredService<DefaultMailboxFilter>());
        builder.Services.AddSingleton<DefaultUserAuthenticator>();
        builder.Services.AddSingleton<IUserAuthenticator>(sp => sp.GetRequiredService<DefaultUserAuthenticator>());
        builder.Services.AddHostedService<SmtpServerHostedService>();

        // **************
        // Build the host
        var host = builder.Build();

        // Configure logging to use TableStorageLoggerProvider
        var loggerFactory = host.Services.GetRequiredService<ILoggerFactory>();
        loggerFactory.AddProvider(host.Services.GetRequiredService<TableStorageLoggerProvider>());
        var logger = host.Services.GetRequiredService<ILogger<Program>>();

        try
        {
            // Log startup
            logger.LogInformation("Starting SMTP Server (Aspire) with settings loaded from appsettings.json");

            // Log relevant environment variables (length only, not values)
            foreach (var kv in Environment.GetEnvironmentVariables().Cast<DictionaryEntry>()
                         .Where(e => e.Key is string s && (s.Contains("BLOB") || s.Contains("TABLE") || s.Contains("STORAGE") || s.Contains("AZURE"))))
            {
                logger.LogDebug("Env {Key} => {Len} chars", kv.Key, kv.Value?.ToString()?.Length ?? 0);
            }

            // Test Azure Storage connectivity
            var blobClient = host.Services.GetRequiredService<BlobServiceClient>();
            // Test TableServiceClient
            var tableClient = host.Services.GetRequiredService<TableServiceClient>();

            // Ensure the SMTPSettings table exists and contains the current settings from appsettings.json
            await StartupStorageHelpers.EnsureSettingsTableAsync(tableClient, smtpConfig, logger);
            await StartupStorageHelpers.TestBlobAsync(blobClient, "email-messages", logger);
            await StartupStorageHelpers.TestTableAsync(tableClient, "SMTPServerLogs", logger);
            await StartupStorageHelpers.TestTableAsync(tableClient, "spamlogs", logger);

            // Run the host
            await host.RunAsync();
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Fatal startup failure");
            throw;
        }
    }
}