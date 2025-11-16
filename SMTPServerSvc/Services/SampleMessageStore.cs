using Azure.Storage.Blobs;
using Microsoft.Extensions.Logging;
using SmtpServer;
using SmtpServer.Protocol;
using SmtpServer.Storage;
using System.Buffers;
using System.Text;
using SMTPServerSvc.Configuration;
using System.Linq;

namespace SMTPServerSvc.Services;

/// <summary>
/// Message store implementation that saves email messages to Azure Blob Storage
/// </summary>
public class SampleMessageStore : MessageStore
{
    // Fix: Mark fields as nullable to resolve CS8618
    private readonly BlobServiceClient? _blobServiceClient;
    private readonly BlobContainerClient? _containerClient;
    private readonly ILogger<SampleMessageStore> _logger;
    private readonly string _containerName;
    private readonly bool _isAvailable;

    public SampleMessageStore(BlobServiceClient blobServiceClient, SmtpServerConfiguration configuration, ILogger<SampleMessageStore> logger)
    {
        _blobServiceClient = blobServiceClient;
        _logger = logger;
        _containerName = "email-messages";

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

            // Determine recipient user folder (first recipient)
            string recipientUser = "unknown";
            try
            {
                var firstTo = transaction.To?.OfType<SmtpServer.Mail.IMailbox>().FirstOrDefault();
                recipientUser = firstTo?.User ?? "unknown";
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Unable to extract recipient user from transaction; defaulting to 'unknown'.");
            }

            // Sanitize recipient for use as a blob virtual folder
            string recipientFolder = SanitizeForBlobPath(recipientUser);

            // Ensure a per-user folder (virtual) by creating a placeholder blob if it doesn't exist
            var keepBlob = _containerClient.GetBlobClient($"{recipientFolder}/.keep");
            try
            {
                if (!await keepBlob.ExistsAsync(cancellationToken))
                {
                    using var empty = new MemoryStream(Array.Empty<byte>());
                    await keepBlob.UploadAsync(empty, cancellationToken: cancellationToken);
                }
            }
            catch (Exception ex)
            {
                // Non-fatal; continue with message upload
                _logger.LogDebug(ex, "Failed to ensure placeholder for folder {Folder}", recipientFolder);
            }

            // Generate unique blob name with timestamp
            var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd_HH-mm-ss-fff");
            var blobName = $"{timestamp}_{sessionId}_{Guid.NewGuid():N}.eml";
            var blobPath = $"{recipientFolder}/{blobName}";

            // Convert buffer to string for storage
            var messageContent = Encoding.UTF8.GetString(buffer.ToArray());

            // Extract Subject/From from the ORIGINAL MIME headers
            static string? HeaderFromOriginal(string content, string key)
            {
                using var sr = new StringReader(content);
                string? l;
                var prefix = key + ":";
                while ((l = sr.ReadLine()) != null)
                {
                    if (string.IsNullOrWhiteSpace(l)) break; // end of original headers
                    if (l.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        return l.Substring(prefix.Length).Trim();
                    }
                }
                return null;
            }

            var originalSubject = HeaderFromOriginal(messageContent, "Subject") ?? "(no subject)";
            var originalFrom = HeaderFromOriginal(messageContent, "From") ?? string.Empty;
            
            // Add metadata preamble (custom headers) followed by a blank line, then original message content
            var enhancedContent = new StringBuilder();
            enhancedContent.AppendLine($"X-SMTP-Server-Received: {DateTime.UtcNow:R}");
            enhancedContent.AppendLine($"X-SMTP-Server-Session: {sessionId}");
            enhancedContent.AppendLine($"X-SMTP-Server-Transaction: {transactionId}");
            enhancedContent.AppendLine($"X-SMTP-Server-BlobName: {blobPath}");
            enhancedContent.AppendLine($"X-SMTP-Server-Recipient-User: {recipientUser}");
            enhancedContent.AppendLine();
            enhancedContent.Append(messageContent);

            // Upload to blob storage under the per-user folder
            var blobClient = _containerClient.GetBlobClient(blobPath);
            
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(enhancedContent.ToString()));
            await blobClient.UploadAsync(stream, overwrite: true, cancellationToken);

            // Set metadata (include Subject/From so the list view can show them without downloading)
            var metadata = new Dictionary<string, string>
            {
                ["SessionId"] = sessionId?.ToString() ?? "unknown",
                ["TransactionId"] = transactionId,
                ["ReceivedAt"] = DateTime.UtcNow.ToString("O"),
                ["MessageSize"] = buffer.Length.ToString(),
                ["ContainerName"] = _containerName,
                ["RecipientUser"] = recipientUser,
                ["Subject"] = originalSubject,
                ["From"] = originalFrom
            };

            await blobClient.SetMetadataAsync(metadata, cancellationToken: cancellationToken);

            _logger.LogInformation("Message saved successfully to blob {BlobName} in container {ContainerName}, size {MessageSize} bytes", 
                blobPath, _containerName, buffer.Length);

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

    private static string SanitizeForBlobPath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "unknown";
        }

        var builder = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            if (char.IsLetterOrDigit(ch) || ch == '.' || ch == '-' || ch == '_')
            {
                builder.Append(ch);
            }
            else
            {
                builder.Append('_');
            }
        }
        var result = builder.ToString().Trim();
        return string.IsNullOrEmpty(result) ? "unknown" : result;
    }
}