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
        var smtpConfig = builder.Configuration.GetSection(SmtpServerConfiguration.SectionName).Get<SmtpServerConfiguration>() ?? new SmtpServerConfiguration();

        // Minimal validation
        if (smtpConfig.Ports is null || smtpConfig.Ports.Length == 0 || string.IsNullOrWhiteSpace(smtpConfig.ServerName))
        {
            var tempLoggerFactory = LoggerFactory.Create(lb => lb.AddConsole());
            var tempLogger = tempLoggerFactory.CreateLogger<Program>();
            tempLogger.LogError("SMTP settings incomplete in appsettings.json. Required settings are missing. Service will stop.");
            return;
        }

        builder.Services.AddSingleton(smtpConfig);

        builder.Services.AddSingleton<IDnsResolver, DnsResolver>();
        builder.Services.AddSingleton<DnsClient.ILookupClient, DnsClient.LookupClient>();
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

        var host = builder.Build();

        var loggerFactory = host.Services.GetRequiredService<ILoggerFactory>();
        loggerFactory.AddProvider(host.Services.GetRequiredService<TableStorageLoggerProvider>());
        var logger = host.Services.GetRequiredService<ILogger<Program>>();

        try
        {
            logger.LogInformation("Starting SMTP Server (Aspire) with settings loaded from appsettings.json");

            foreach (var kv in Environment.GetEnvironmentVariables().Cast<DictionaryEntry>()
                         .Where(e => e.Key is string s && (s.Contains("BLOB") || s.Contains("TABLE") || s.Contains("STORAGE") || s.Contains("AZURE"))))
            {
                logger.LogDebug("Env {Key} => {Len} chars", kv.Key, kv.Value?.ToString()?.Length ?? 0);
            }

            var blobClient = host.Services.GetRequiredService<BlobServiceClient>();
            var tableClient = host.Services.GetRequiredService<TableServiceClient>();

            // Ensure the SMTPSettings table exists and contains the current settings from appsettings.json
            await EnsureSettingsTableAsync(tableClient, smtpConfig, logger);
            await TestBlobAsync(blobClient, "email-messages", logger);
            await TestTableAsync(tableClient, "SMTPServerLogs", logger);
            await TestTableAsync(tableClient, "spamlogs", logger);

            await host.RunAsync();
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Fatal startup failure");
            throw;
        }
    }

    private static async Task EnsureSettingsTableAsync(TableServiceClient tableServiceClient, SmtpServerConfiguration cfg, ILogger logger)
    {
        const string SettingsTableName = "SMTPSettings";
        const string PartitionKey = "SmtpServer";
        const string RowKey = "Current";

        try
        {
            logger.LogInformation("Ensuring settings table '{Table}' exists and is populated", SettingsTableName);
            var table = tableServiceClient.GetTableClient(SettingsTableName);
            await table.CreateIfNotExistsAsync();

            var portsCsv = string.Join(", ", cfg.Ports ?? Array.Empty<int>());
            var portsJson = JsonSerializer.Serialize(cfg.Ports ?? Array.Empty<int>());

            var entity = new TableEntity(PartitionKey, RowKey)
            {
                { "ServerName", cfg.ServerName ?? string.Empty },
                { "Ports", portsCsv },
                { "PortsJson", portsJson },
                { "AllowedRecipient", cfg.AllowedRecipient ?? string.Empty },
                { "AllowedUsername", cfg.AllowedUsername ?? string.Empty },
                { "AllowedPassword", cfg.AllowedPassword ?? string.Empty },
                { "SpamhausKey", cfg.SpamhausKey ?? string.Empty },
                { "EnableSpamFiltering", cfg.EnableSpamFiltering },
                { "EnableSpfCheck", cfg.EnableSpfCheck },
                { "EnableDmarcCheck", cfg.EnableDmarcCheck },
                { "EnableDkimCheck", cfg.EnableDkimCheck }
            };

            await table.UpsertEntityAsync(entity);
            logger.LogInformation("SMTP settings written to table '{Table}'", SettingsTableName);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to write SMTP settings to table");
        }
    }

    private static async Task TestBlobAsync(BlobServiceClient blobServiceClient, string container, ILogger logger)
    {
        try
        {
            logger.LogInformation("Blob Service URI: {Uri}", blobServiceClient.Uri);
            var c = blobServiceClient.GetBlobContainerClient(container);
            await c.CreateIfNotExistsAsync();
            logger.LogInformation("Blob container '{Container}' ready", container);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Blob connectivity failed {Message}", ex.Message);
        }
    }

    private static async Task TestTableAsync(TableServiceClient tableServiceClient, string tableName, ILogger logger)
    {
        try
        {
            logger.LogInformation("Table Service URI: {Uri}", tableServiceClient.Uri);
            var t = tableServiceClient.GetTableClient(tableName);
            await t.CreateIfNotExistsAsync();
            logger.LogInformation("Table '{Table}' ready", tableName);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Table connectivity failed {Message}", ex.Message);
        }
    }
}
