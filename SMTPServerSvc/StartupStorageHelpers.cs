using Azure.Storage.Blobs;
using Azure.Data.Tables;
using Microsoft.Extensions.Logging;
using SMTPServerSvc.Configuration;
using System.Text.Json;

namespace SMTPServerSvc;

internal static class StartupStorageHelpers
{
    internal static async Task EnsureSettingsTableAsync(TableServiceClient tableServiceClient, SmtpServerConfiguration cfg, ILogger logger)
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

    internal static async Task TestBlobAsync(BlobServiceClient blobServiceClient, string container, ILogger logger)
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

    internal static async Task TestTableAsync(TableServiceClient tableServiceClient, string tableName, ILogger logger)
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
