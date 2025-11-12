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

namespace SMTPServerSvc;

internal class Program
{
    static async Task Main(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);
        builder.AddServiceDefaults();

        // Do NOT re-add appsettings.json forcibly; Aspire already wires configuration including env vars
        var smtpConfig = builder.Configuration.GetSection(SmtpServerConfiguration.SectionName).Get<SmtpServerConfiguration>()
                         ?? throw new InvalidOperationException($"Missing '{SmtpServerConfiguration.SectionName}' configuration section.");

        // Minimal validation (storage connection comes from Aspire binding env vars)
        if (smtpConfig.Ports is null || smtpConfig.Ports.Length == 0) throw new InvalidOperationException("SmtpServer:Ports required");
        if (string.IsNullOrWhiteSpace(smtpConfig.BlobContainerName)) throw new InvalidOperationException("SmtpServer:BlobContainerName required");
        if (string.IsNullOrWhiteSpace(smtpConfig.LogTableName)) throw new InvalidOperationException("SmtpServer:LogTableName required");

        builder.Services.AddSingleton(smtpConfig);

        // Register Azure clients from Aspire resource references (names must match AppHost: blobs, tables)
        builder.AddAzureBlobServiceClient("blobs");
        builder.AddAzureTableServiceClient("tables");

        // Custom logger provider (table name comes from config)
        builder.Services.AddSingleton<TableStorageLoggerProvider>(sp =>
        {
            var tableServiceClient = sp.GetRequiredService<TableServiceClient>();
            var cfg = sp.GetRequiredService<SmtpServerConfiguration>();
            return new TableStorageLoggerProvider(tableServiceClient, cfg.LogTableName);
        });

        // SMTP components
        builder.Services.AddSingleton<SampleMessageStore>();
        builder.Services.AddSingleton<IMessageStore>(sp => sp.GetRequiredService<SampleMessageStore>());
        builder.Services.AddSingleton<SampleMailboxFilter>();
        builder.Services.AddSingleton<IMailboxFilter>(sp => sp.GetRequiredService<SampleMailboxFilter>());
        builder.Services.AddSingleton<SampleUserAuthenticator>();
        builder.Services.AddSingleton<IUserAuthenticator>(sp => sp.GetRequiredService<SampleUserAuthenticator>());
        builder.Services.AddHostedService<StorageDiagnosticService>();
        builder.Services.AddHostedService<SmtpServerHostedService>();

        var host = builder.Build();

        var loggerFactory = host.Services.GetRequiredService<ILoggerFactory>();
        loggerFactory.AddProvider(host.Services.GetRequiredService<TableStorageLoggerProvider>());
        var logger = host.Services.GetRequiredService<ILogger<Program>>();

        try
        {
            logger.LogInformation("Starting SMTP Server (Aspire)");

            // Dump resolved connection environment vars for diagnostics (sanitized)
            foreach (var kv in Environment.GetEnvironmentVariables().Cast<DictionaryEntry>()
                         .Where(e => e.Key is string s && (s.Contains("BLOB") || s.Contains("TABLE") || s.Contains("STORAGE") || s.Contains("AZURE"))) )
            {
                logger.LogDebug("Env {Key} => {Len} chars", kv.Key, kv.Value?.ToString()?.Length ?? 0);
            }

            // Test clients early with short timeout + custom retry to surface issues once (not 6x default)
            var blobClient = host.Services.GetRequiredService<BlobServiceClient>();
            var tableClient = host.Services.GetRequiredService<TableServiceClient>();

            await TestBlobAsync(blobClient, smtpConfig.BlobContainerName, logger);
            await TestTableAsync(tableClient, smtpConfig.LogTableName, logger);

            await host.RunAsync();
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Fatal startup failure");
            throw;
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
