using Azure.Storage.Blobs;
using Microsoft.Extensions.Logging;
using SmtpServer;
using SmtpServer.Protocol;
using SmtpServer.Storage;
using System.Buffers;
using System.Text;

namespace SMTPServerSvc.Services;

/// <summary>
/// Message store implementation that saves email messages to Azure Blob Storage
/// </summary>
public class SampleMessageStore : MessageStore
{
    private readonly BlobServiceClient _blobServiceClient;
    private readonly BlobContainerClient _containerClient;
    private readonly ILogger<SampleMessageStore> _logger;

    public SampleMessageStore(BlobServiceClient blobServiceClient, ILogger<SampleMessageStore> logger)
    {
        _blobServiceClient = blobServiceClient;
        _logger = logger;
        
        // Create container for email messages
        _containerClient = _blobServiceClient.GetBlobContainerClient("email-messages");
        _containerClient.CreateIfNotExists();
        
        _logger.LogInformation("SampleMessageStore initialized with blob container: {ContainerName}", "email-messages");
    }

    public override async Task<SmtpResponse> SaveAsync(ISessionContext context, IMessageTransaction transaction, ReadOnlySequence<byte> buffer, CancellationToken cancellationToken)
    {
        try
        {
            _logger.LogInformation("Saving message for session {SessionId}, transaction {TransactionId}", 
                context.Properties.ContainsKey("SessionId") ? context.Properties["SessionId"] : "unknown", 
                transaction.GetHashCode());

            // Generate unique blob name with timestamp
            var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd_HH-mm-ss-fff");
            var sessionId = context.Properties.ContainsKey("SessionId") ? context.Properties["SessionId"] : "unknown";
            var blobName = $"{timestamp}_{sessionId}_{Guid.NewGuid():N}.eml";

            // Convert buffer to string for storage
            var messageContent = Encoding.UTF8.GetString(buffer.ToArray());
            
            // Add metadata to the message
            var enhancedContent = new StringBuilder();
            enhancedContent.AppendLine($"X-SMTP-Server-Received: {DateTime.UtcNow:R}");
            enhancedContent.AppendLine($"X-SMTP-Server-Session: {sessionId}");
            enhancedContent.AppendLine($"X-SMTP-Server-Transaction: {transaction.GetHashCode()}");
            
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
                ["TransactionId"] = transaction.GetHashCode().ToString(),
                ["ReceivedAt"] = DateTime.UtcNow.ToString("O"),
                ["MessageSize"] = buffer.Length.ToString()
            };

            await blobClient.SetMetadataAsync(metadata, cancellationToken: cancellationToken);

            _logger.LogInformation("Message saved successfully to blob {BlobName}, size {MessageSize} bytes", 
                blobName, buffer.Length);

            return SmtpResponse.Ok;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save message to blob storage");
            return new SmtpResponse(SmtpReplyCode.InsufficientStorage, "Failed to store message");
        }
    }
}