using Azure.Data.Tables;
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
public class DefaultMessageStore : MessageStore
{
    private readonly BlobServiceClient? _blobServiceClient;
    private readonly BlobContainerClient? _containerClient;
    private readonly TableClient? _spamLogTableClient;
    private readonly ILogger<DefaultMessageStore> _logger;
    private readonly string _containerName;
    private readonly bool _isAvailable;

    public DefaultMessageStore(BlobServiceClient blobServiceClient, TableServiceClient tableServiceClient, SmtpServerConfiguration configuration, ILogger<DefaultMessageStore> logger)
    {
        _blobServiceClient = blobServiceClient;
        _logger = logger;
        _containerName = "email-messages";

        try
        {
            _logger.LogInformation("Initializing DefaultMessageStore with Aspire-managed clients");

            // Create container for email messages
            _containerClient = _blobServiceClient.GetBlobContainerClient(_containerName);
            _containerClient.CreateIfNotExists();

            // Initialize spam logs table
            _spamLogTableClient = tableServiceClient.GetTableClient("spamlogs");
            _spamLogTableClient.CreateIfNotExists();

            _isAvailable = true;

            _logger.LogInformation("DefaultMessageStore initialized successfully");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to initialize storage. Messages will be logged but not stored.");
            _containerClient = null!;
            _spamLogTableClient = null;
            _isAvailable = false;
        }
    }

    public override async Task<SmtpResponse> SaveAsync(ISessionContext context, IMessageTransaction transaction, ReadOnlySequence<byte> buffer, CancellationToken cancellationToken)
    {
        try
        {
            var sessionId = context.Properties.ContainsKey("SessionId") ? context.Properties["SessionId"] : "unknown";
            var transactionId = transaction.GetHashCode().ToString();

            // Check for spam tag
            bool isSpam = context.Properties.ContainsKey("IsSpam") && (bool)context.Properties["IsSpam"];
            var targetContainer = isSpam ? "spam-messages" : _containerName;

            _logger.LogInformation("Saving message for session {SessionId}, transaction {TransactionId}, size {MessageSize} bytes. IsSpam: {IsSpam}",
                sessionId, transactionId, buffer.Length, isSpam);

            // If blob storage is not available, log message content and return success
            if (!_isAvailable || _containerClient == null)
            {
                _logger.LogWarning("Blob storage unavailable. Message content will be logged only:");

                // Convert buffer to string for logging
                var logMessageContent = Encoding.UTF8.GetString(buffer.ToArray());
                _logger.LogInformation("Message Content (Session {SessionId}):\n{MessageContent}", sessionId, logMessageContent);

                return SmtpResponse.Ok; // Still return OK to not break SMTP flow
            }

            // Get the correct container client
            var containerClient = isSpam ? _blobServiceClient!.GetBlobContainerClient(targetContainer) : _containerClient;
            await containerClient.CreateIfNotExistsAsync(cancellationToken: cancellationToken);

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
            if (isSpam) enhancedContent.AppendLine("X-SMTP-Server-Spam: True");
            enhancedContent.AppendLine();
            enhancedContent.Append(messageContent);

            // Upload to blob storage under the per-user folder
            var blobClient = containerClient.GetBlobClient(blobPath);

            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(enhancedContent.ToString()));
            await blobClient.UploadAsync(stream, overwrite: true, cancellationToken);

            // Set metadata (include Subject/From so the list view can show them without downloading)
            var metadata = new Dictionary<string, string>
            {
                ["SessionId"] = sessionId?.ToString() ?? "unknown",
                ["TransactionId"] = transactionId,
                ["ReceivedAt"] = DateTime.UtcNow.ToString("O"),
                ["MessageSize"] = buffer.Length.ToString(),
                ["ContainerName"] = targetContainer,
                ["RecipientUser"] = recipientUser,
                ["Subject"] = originalSubject,
                ["From"] = originalFrom,
                ["IsSpam"] = isSpam.ToString()
            };

            await blobClient.SetMetadataAsync(metadata, cancellationToken: cancellationToken);

            _logger.LogInformation("Message saved successfully to blob {BlobName} in container {ContainerName}, size {MessageSize} bytes",
                blobPath, targetContainer, buffer.Length);

            if (isSpam)
            {
                // Extract IP address from context
                string ipAddress = "unknown";
                if (context.Properties.ContainsKey("SpamIP"))
                {
                    ipAddress = context.Properties["SpamIP"]?.ToString() ?? "unknown";
                }
                else if (context.Properties.TryGetValue("RemoteEndPoint", out var endpointObj) && endpointObj is System.Net.IPEndPoint ipEndPoint)
                {
                    ipAddress = ipEndPoint.Address.ToString();
                }

                await LogSpamAsync(sessionId?.ToString() ?? "unknown", transactionId, originalFrom, recipientUser, originalSubject, blobPath, ipAddress);
            }

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

    private async Task LogSpamAsync(string sessionId, string transactionId, string from, string to, string subject, string blobPath, string ip)
    {
        if (_spamLogTableClient == null) return;

        try
        {
            var entity = new TableEntity
            {
                PartitionKey = DateTime.UtcNow.ToString("yyyy-MM-dd"),
                RowKey = $"{DateTime.UtcNow:HHmmss.fff}_{Guid.NewGuid():N}",
                ["Timestamp"] = DateTime.UtcNow,
                ["SessionId"] = sessionId,
                ["TransactionId"] = transactionId,
                ["From"] = from,
                ["To"] = to,
                ["Subject"] = subject,
                ["BlobPath"] = blobPath,
                ["IP"] = ip
            };

            await _spamLogTableClient.AddEntityAsync(entity);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to log spam entry to table storage");
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