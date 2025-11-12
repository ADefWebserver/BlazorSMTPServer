using Azure.Storage.Blobs;
using Microsoft.Extensions.Logging;
using SmtpServer;
using SmtpServer.Protocol;
using SmtpServer.Storage;
using System.Buffers;
using System.Text;
using SMTPServerSvc.Configuration;

namespace SMTPServerSvc.Services;

/// <summary>
/// Message store implementation that saves email messages to Azure Blob Storage
/// </summary>
public class SampleMessageStore : MessageStore
{
    private readonly BlobServiceClient _blobServiceClient;
    private readonly BlobContainerClient _containerClient;
    private readonly ILogger<SampleMessageStore> _logger;
    private readonly string _containerName;
    private readonly bool _isAvailable;

    public SampleMessageStore(BlobServiceClient blobServiceClient, SmtpServerConfiguration configuration, ILogger<SampleMessageStore> logger)
    {
        _blobServiceClient = blobServiceClient;
        _logger = logger;
        _containerName = configuration.BlobContainerName;

        try
        {
            _logger.LogInformation("Initializing SampleMessageStore with Aspire-managed BlobServiceClient");
            _logger.LogInformation("  Blob Service URI: {BlobUri}", _blobServiceClient.Uri);
            _logger.LogInformation("  Container Name: {ContainerName}", _containerName);

            // Create container for email messages
            _containerClient = _blobServiceClient.GetBlobContainerClient(_containerName);
            
            // Test connectivity and create container
            _containerClient.CreateIfNotExists();
            _isAvailable = true;
            
            _logger.LogInformation("SampleMessageStore initialized successfully with container: {ContainerName}", _containerName);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to initialize blob storage. Messages will be logged but not stored.");
            _logger.LogWarning("  Blob Service URI: {BlobUri}", _blobServiceClient?.Uri?.ToString() ?? "NULL");
            _logger.LogWarning("  Container Name: {ContainerName}", _containerName);
            _logger.LogWarning("  Error: {ErrorMessage}", ex.Message);
            
            _containerClient = null!;
            _isAvailable = false;
        }
    }

    public override async Task<SmtpResponse> SaveAsync(ISessionContext context, IMessageTransaction transaction, ReadOnlySequence<byte> buffer, CancellationToken cancellationToken)
    {
        try
        {
            var sessionId = context.Properties.ContainsKey("SessionId") ? context.Properties["SessionId"] : "unknown";
            var transactionId = transaction.GetHashCode().ToString();
            
            _logger.LogInformation("Saving message for session {SessionId}, transaction {TransactionId}, size {MessageSize} bytes", 
                sessionId, transactionId, buffer.Length);

            // If blob storage is not available, log message content and return success
            if (!_isAvailable || _containerClient == null)
            {
                _logger.LogWarning("Blob storage unavailable. Message content will be logged only:");
                
                // Convert buffer to string for logging
                var logMessageContent = Encoding.UTF8.GetString(buffer.ToArray());
                _logger.LogInformation("Message Content (Session {SessionId}):\n{MessageContent}", sessionId, logMessageContent);
                
                return SmtpResponse.Ok; // Still return OK to not break SMTP flow
            }

            // Generate unique blob name with timestamp
            var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd_HH-mm-ss-fff");
            var blobName = $"{timestamp}_{sessionId}_{Guid.NewGuid():N}.eml";

            // Convert buffer to string for storage
            var messageContent = Encoding.UTF8.GetString(buffer.ToArray());
            
            // Add metadata to the message
            var enhancedContent = new StringBuilder();
            enhancedContent.AppendLine($"X-SMTP-Server-Received: {DateTime.UtcNow:R}");
            enhancedContent.AppendLine($"X-SMTP-Server-Session: {sessionId}");
            enhancedContent.AppendLine($"X-SMTP-Server-Transaction: {transactionId}");
            enhancedContent.AppendLine($"X-SMTP-Server-BlobName: {blobName}");
            
            // Add original message content
            enhancedContent.AppendLine();
            enhancedContent.Append(messageContent);

            // Upload to blob storage
            var blobClient = _containerClient.GetBlobClient(blobName);
            
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(enhancedContent.ToString()));
            await blobClient.UploadAsync(stream, overwrite: true, cancellationToken);

            // Set metadata
            var metadata = new Dictionary<string, string>
            {
                ["SessionId"] = sessionId?.ToString() ?? "unknown",
                ["TransactionId"] = transactionId,
                ["ReceivedAt"] = DateTime.UtcNow.ToString("O"),
                ["MessageSize"] = buffer.Length.ToString(),
                ["ContainerName"] = _containerName
            };

            await blobClient.SetMetadataAsync(metadata, cancellationToken: cancellationToken);

            _logger.LogInformation("Message saved successfully to blob {BlobName} in container {ContainerName}, size {MessageSize} bytes", 
                blobName, _containerName, buffer.Length);

            return SmtpResponse.Ok;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save message to blob storage. Error: {ErrorMessage}", ex.Message);
            
            // Log the message content as fallback
            try
            {
                var messageContent = Encoding.UTF8.GetString(buffer.ToArray());
                _logger.LogInformation("Message content (fallback logging):\n{MessageContent}", messageContent);
            }
            catch (Exception logEx)
            {
                _logger.LogError(logEx, "Failed to log message content as fallback");
            }
            
            return SmtpResponse.Ok; // Return OK to not break SMTP flow, even if storage fails
        }
    }
}