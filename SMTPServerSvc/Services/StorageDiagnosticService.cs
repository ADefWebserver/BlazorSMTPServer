using Azure.Storage.Blobs;
using Azure.Data.Tables;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SMTPServerSvc.Configuration;

namespace SMTPServerSvc.Services;

/// <summary>
/// Diagnostic service to test Azure Storage connectivity at startup
/// </summary>
public class StorageDiagnosticService : IHostedService
{
    private readonly ILogger<StorageDiagnosticService> _logger;
    private readonly BlobServiceClient _blobServiceClient;
    private readonly TableServiceClient _tableServiceClient;
    private readonly SmtpServerConfiguration _configuration;

    public StorageDiagnosticService(
        BlobServiceClient blobServiceClient,
        TableServiceClient tableServiceClient,
        SmtpServerConfiguration configuration,
        ILogger<StorageDiagnosticService> logger)
    {
        _blobServiceClient = blobServiceClient;
        _tableServiceClient = tableServiceClient;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Starting Storage Diagnostic Service...");
        
        await DiagnoseBlobStorage(cancellationToken);
        await DiagnoseTableStorage(cancellationToken);
        
        _logger.LogInformation("Storage Diagnostic Service completed.");
    }

    private async Task DiagnoseBlobStorage(CancellationToken cancellationToken)
    {
        try
        {
            _logger.LogInformation("=== Blob Storage Diagnostics ===");
            _logger.LogInformation("  Service URI: {BlobUri}", _blobServiceClient.Uri);
            _logger.LogInformation("  Account Name: {AccountName}", _blobServiceClient.AccountName);
            
            // Test basic connectivity
            _logger.LogInformation("  Testing basic connectivity...");
            var properties = await _blobServiceClient.GetPropertiesAsync(cancellationToken);
            _logger.LogInformation("  ? Basic connectivity successful");
            
            // Test container operations
            _logger.LogInformation("  Testing container operations...");
            var containerClient = _blobServiceClient.GetBlobContainerClient(_configuration.BlobContainerName);
            await containerClient.CreateIfNotExistsAsync(cancellationToken: cancellationToken);
            _logger.LogInformation("  ? Container '{ContainerName}' created/verified", _configuration.BlobContainerName);
            
            // Test blob operations
            _logger.LogInformation("  Testing blob operations...");
            var testBlobName = $"diagnostic-test-{DateTime.UtcNow:yyyy-MM-dd-HH-mm-ss}.txt";
            var blobClient = containerClient.GetBlobClient(testBlobName);
            
            using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes("Diagnostic test content"));
            await blobClient.UploadAsync(stream, overwrite: true, cancellationToken);
            _logger.LogInformation("  ? Test blob '{BlobName}' uploaded successfully", testBlobName);
            
            // Clean up test blob
            await blobClient.DeleteIfExistsAsync(cancellationToken: cancellationToken);
            _logger.LogInformation("  ? Test blob cleaned up");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Blob Storage diagnostic failed: {ErrorMessage}", ex.Message);
            _logger.LogError("  Service URI: {BlobUri}", _blobServiceClient?.Uri?.ToString() ?? "NULL");
        }
    }

    private async Task DiagnoseTableStorage(CancellationToken cancellationToken)
    {
        try
        {
            _logger.LogInformation("=== Table Storage Diagnostics ===");
            _logger.LogInformation("  Service URI: {TableUri}", _tableServiceClient.Uri);
            _logger.LogInformation("  Account Name: {AccountName}", _tableServiceClient.AccountName);
            
            // Test basic connectivity
            _logger.LogInformation("  Testing basic connectivity...");
            var properties = await _tableServiceClient.GetPropertiesAsync(cancellationToken);
            _logger.LogInformation("  ? Basic connectivity successful");
            
            // Test table operations
            _logger.LogInformation("  Testing table operations...");
            var tableClient = _tableServiceClient.GetTableClient(_configuration.LogTableName);
            await tableClient.CreateIfNotExistsAsync(cancellationToken);
            _logger.LogInformation("  ? Table '{TableName}' created/verified", _configuration.LogTableName);
            
            // Test entity operations
            _logger.LogInformation("  Testing entity operations...");
            var testEntity = new TableEntity("diagnostic", $"test-{DateTime.UtcNow.Ticks}")
            {
                ["Message"] = "Diagnostic test",
                ["Timestamp"] = DateTime.UtcNow
            };
            
            await tableClient.AddEntityAsync(testEntity, cancellationToken);
            _logger.LogInformation("  ? Test entity added successfully");
            
            // Clean up test entity
            await tableClient.DeleteEntityAsync(testEntity.PartitionKey, testEntity.RowKey, cancellationToken: cancellationToken);
            _logger.LogInformation("  ? Test entity cleaned up");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Table Storage diagnostic failed: {ErrorMessage}", ex.Message);
            _logger.LogError("  Service URI: {TableUri}", _tableServiceClient?.Uri?.ToString() ?? "NULL");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Storage Diagnostic Service stopped.");
        return Task.CompletedTask;
    }
}