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

        // Add Azure clients from Aspire resource references (names must match AppHost: blobs, tables)
        builder.AddAzureBlobServiceClient("blobs");
        builder.AddAzureTableServiceClient("tables");

        // Attempt to load settings from Azure Table 'SMPTSettings'
        // Use a provisional TableServiceClient (Aspire will also provide one later for DI)
        var provisionalTableClient = new TableServiceClient("UseDevelopmentStorage=true");
        var settingsLoader = new TableSettingsLoader(provisionalTableClient, null);
        var smtpConfig = await settingsLoader.TryLoadAsync();
        if (smtpConfig == null)
        {
            var tempLoggerFactory = LoggerFactory.Create(lb => lb.AddConsole());
            var tempLogger = tempLoggerFactory.CreateLogger<Program>();
            tempLogger.LogError("SMTP settings missing or incomplete in table 'SMPTSettings'. Service will stop.");
            return; // Stop service
        }

        // Minimal validation
        if (smtpConfig.Ports is null || smtpConfig.Ports.Length == 0 || string.IsNullOrWhiteSpace(smtpConfig.BlobContainerName) || string.IsNullOrWhiteSpace(smtpConfig.LogTableName) || string.IsNullOrWhiteSpace(smtpConfig.ServerName))
        {
            var tempLoggerFactory = LoggerFactory.Create(lb => lb.AddConsole());
            var tempLogger = tempLoggerFactory.CreateLogger<Program>();
            tempLogger.LogError("SMTP settings incomplete. Required settings are missing. Service will stop.");
            return;
        }

        builder.Services.AddSingleton(smtpConfig);

        // Custom logger provider (table name comes from config)
        builder.Services.AddSingleton<TableStorageLoggerProvider>(sp =>
        {
            var tableSvcClient = sp.GetRequiredService<TableServiceClient>();
            var cfg = sp.GetRequiredService<SmtpServerConfiguration>();
            return new TableStorageLoggerProvider(tableSvcClient, cfg.LogTableName);
        });

        // SMTP components
        builder.Services.AddSingleton<SampleMessageStore>();
        builder.Services.AddSingleton<IMessageStore>(sp => sp.GetRequiredService<SampleMessageStore>());
        builder.Services.AddSingleton<SampleMailboxFilter>();
        builder.Services.AddSingleton<IMailboxFilter>(sp => sp.GetRequiredService<SampleMailboxFilter>());
        builder.Services.AddSingleton<SampleUserAuthenticator>();
        builder.Services.AddSingleton<IUserAuthenticator>(sp => sp.GetRequiredService<SampleUserAuthenticator>()); // fixed missing dot
        builder.Services.AddHostedService<SmtpServerHostedService>();

        var host = builder.Build();

        var loggerFactory = host.Services.GetRequiredService<ILoggerFactory>();
        loggerFactory.AddProvider(host.Services.GetRequiredService<TableStorageLoggerProvider>());
        var logger = host.Services.GetRequiredService<ILogger<Program>>();

        try
        {
            logger.LogInformation("Starting SMTP Server (Aspire) with settings loaded from table");

            foreach (var kv in Environment.GetEnvironmentVariables().Cast<DictionaryEntry>()
                         .Where(e => e.Key is string s && (s.Contains("BLOB") || s.Contains("TABLE") || s.Contains("STORAGE") || s.Contains("AZURE"))) )
            {
                logger.LogDebug("Env {Key} => {Len} chars", kv.Key, kv.Value?.ToString()?.Length ?? 0);
            }

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

public class TableSettingsLoader
{
    private readonly TableServiceClient _tableServiceClient;
    private readonly ILogger? _logger;
    private const string TableName = "SMPTSettings"; // requested spelling
    private const string PartitionKey = "SmtpServer";
    private const string RowKey = "Current";

    public TableSettingsLoader(TableServiceClient tableServiceClient, ILogger<TableSettingsLoader>? logger)
    {
        _tableServiceClient = tableServiceClient;
        _logger = logger;
    }

    public async Task<SmtpServerConfiguration?> TryLoadAsync()
    {
        try
        {
            var table = _tableServiceClient.GetTableClient(TableName);
            // Attempt to create (will succeed if missing) then load; if newly created, no settings yet
            await table.CreateIfNotExistsAsync();
            var entityResp = await table.GetEntityIfExistsAsync<TableEntity>(PartitionKey, RowKey);
            if (!entityResp.HasValue)
            {
                _logger?.LogError("Settings entity missing in table '{TableName}'", TableName);
                return null;
            }
            var e = entityResp.Value;
            var config = new SmtpServerConfiguration
            {
                ServerName = e.GetString("ServerName") ?? string.Empty,
                AllowedRecipient = e.GetString("AllowedRecipient") ?? string.Empty,
                AllowedUsername = e.GetString("AllowedUsername") ?? string.Empty,
                AllowedPassword = e.GetString("AllowedPassword") ?? string.Empty,
                BlobContainerName = e.GetString("BlobContainerName") ?? string.Empty,
                LogTableName = e.GetString("LogTableName") ?? string.Empty,
                Ports = (e.GetString("Ports") ?? string.Empty)
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(p => int.TryParse(p, out var v) ? v : 0).Where(v => v > 0).ToArray()
            };
            if (config.Ports.Length == 0 && e.TryGetValue("PortsJson", out var portsJsonObj) && portsJsonObj is string portsJson && !string.IsNullOrEmpty(portsJson))
            {
                try { config.Ports = JsonSerializer.Deserialize<int[]>(portsJson) ?? Array.Empty<int>(); } catch { }
            }
            _logger?.LogInformation("SMTP settings loaded from table.");
            return config;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to load settings");
            return null;
        }
    }
}
