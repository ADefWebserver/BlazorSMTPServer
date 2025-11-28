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
using MimeKit;
using MimeKit.Cryptography;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using System.IO;

namespace SMTPServerSvc.Services;

/// <summary>
/// Message store implementation that saves email messages to Azure Blob Storage
/// </summary>
public class DefaultMessageStore : MessageStore
{
    private readonly BlobServiceClient? _blobServiceClient;
    private readonly BlobContainerClient? _containerClient;
    private readonly TableClient? _spamLogTableClient;
    private readonly TableClient? _settingsTableClient;
    private readonly ILogger<DefaultMessageStore> _logger;
    private readonly SmtpServerConfiguration _configuration;
    private readonly MailAuthenticationService _authService;
    private readonly string _containerName;
    private readonly bool _isAvailable;

    public DefaultMessageStore(BlobServiceClient blobServiceClient, TableServiceClient tableServiceClient, SmtpServerConfiguration configuration, ILogger<DefaultMessageStore> logger, MailAuthenticationService authService)
    {
        _blobServiceClient = blobServiceClient;
        _logger = logger;
        _configuration = configuration;
        _authService = authService;
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

            // Initialize settings table
            _settingsTableClient = tableServiceClient.GetTableClient("SMTPSettings");
            _settingsTableClient.CreateIfNotExists();

            _isAvailable = true;

            _logger.LogInformation("DefaultMessageStore initialized successfully");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to initialize storage. Messages will be logged but not stored.");
            _containerClient = null!;
            _spamLogTableClient = null;
            _settingsTableClient = null;
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
            var containerClient = isSpam ? _blobServiceClient!.GetBlobContainerClient(_containerName) : _containerClient;
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

            if (isSpam)
            {
                // This will force the blob to go into a 'spam' folder
                // regardless of recipient
                // if it has been marked as spam
                recipientFolder = "spam";
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

            // ******************************************************************************************************************************
            // DKIM & DMARC Validation (Requires full message content)
            // ******************************************************************************************************************************
            bool dkimPass = false;
            bool dmarcPass = false;
            string? dkimSignature = HeaderFromOriginal(messageContent, "DKIM-Signature");

            if (_configuration.EnableDkimCheck && !string.IsNullOrEmpty(dkimSignature))
            {
                dkimPass = await _authService.ValidateDkimAsync(dkimSignature);
                if (!dkimPass)
                {
                    _logger.LogWarning("DKIM Validation Failed for {From}", originalFrom);
                }
                else
                {
                    _logger.LogInformation("DKIM Validation Passed for {From}", originalFrom);
                }
            }

            if (_configuration.EnableDmarcCheck)
            {
                // Retrieve SPF result from context (set in DefaultMailboxFilter)
                bool spfPass = context.Properties.ContainsKey("SpfPass") && (bool)context.Properties["SpfPass"];
                string fromDomain = context.Properties.ContainsKey("FromDomain") ? (string)context.Properties["FromDomain"] : "";

                // DMARC requires SPF OR DKIM to pass (and align)
                // Simplified check: if either passed, we consider DMARC passed for now.
                // Real DMARC requires checking alignment of From domain with SPF/DKIM domains.
                
                if (spfPass || dkimPass)
                {
                    dmarcPass = true;
                    _logger.LogInformation("DMARC Check Passed (SPF: {Spf}, DKIM: {Dkim})", spfPass, dkimPass);
                }
                else
                {
                    // Fetch policy to see if we should reject
                    if (!string.IsNullOrEmpty(fromDomain))
                    {
                        var policy = await _authService.GetDmarcPolicyAsync(fromDomain);
                        _logger.LogWarning("DMARC Check Failed for {Domain}. Policy: {Policy}", fromDomain, policy ?? "none");
                        
                        if (policy == "reject" || policy == "quarantine")
                        {
                            isSpam = true; // Mark as spam
                        }
                    }
                }
            }
            // ******************************************************************************************************************************

            // Parse message for modification
            var message = MimeMessage.Load(new MemoryStream(buffer.ToArray()));

            // Add metadata headers
            message.Headers.Add("X-SMTP-Server-Received", DateTime.UtcNow.ToString("R"));
            message.Headers.Add("X-SMTP-Server-Session", sessionId?.ToString() ?? "unknown");
            message.Headers.Add("X-SMTP-Server-Transaction", transactionId);
            message.Headers.Add("X-SMTP-Server-BlobName", blobPath);
            message.Headers.Add("X-SMTP-Server-Recipient-User", recipientUser);
            if (isSpam) message.Headers.Add("X-SMTP-Server-Spam", "True");
            if (dkimPass) message.Headers.Add("X-SMTP-Server-DKIM", "Pass");
            if (dmarcPass) message.Headers.Add("X-SMTP-Server-DMARC", "Pass");

            // DKIM Signing
            if (_settingsTableClient != null)
            {
                try
                {
                    var settings = await _settingsTableClient.GetEntityIfExistsAsync<TableEntity>("SmtpServer", "Current");
                    if (settings.HasValue && settings.Value != null)
                    {
                        var enableDkimSigning = settings.Value.GetBoolean("EnableDkimSigning") ?? false;
                        var dkimPrivateKey = settings.Value.GetString("DkimPrivateKey");
                        var dkimSelector = settings.Value.GetString("DkimSelector");
                        var dkimDomain = settings.Value.GetString("DkimDomain");

                        if (enableDkimSigning && !string.IsNullOrEmpty(dkimPrivateKey) && !string.IsNullOrEmpty(dkimSelector) && !string.IsNullOrEmpty(dkimDomain))
                        {
                            _logger.LogInformation("Signing message with DKIM for domain {Domain}, selector {Selector}", dkimDomain, dkimSelector);
                            SignMessage(message, dkimDomain, dkimSelector, dkimPrivateKey);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error reading settings or signing message");
                }
            }

            // Upload to blob storage under the per-user folder
            var blobClient = containerClient.GetBlobClient(blobPath);

            using var stream = new MemoryStream();
            await message.WriteToAsync(stream);
            stream.Position = 0;
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
                ["From"] = originalFrom,
                ["IsSpam"] = isSpam.ToString()
            };

            await blobClient.SetMetadataAsync(metadata, cancellationToken: cancellationToken);

            _logger.LogInformation("Message saved successfully to blob {BlobName} in container {ContainerName}, size {MessageSize} bytes",
                blobPath, _containerName, buffer.Length);

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

    private void SignMessage(MimeMessage message, string domain, string selector, string privateKeyPem)
    {
        try
        {
            using var reader = new StringReader(privateKeyPem);
            var pemReader = new PemReader(reader);
            var keyObject = pemReader.ReadObject();

            AsymmetricKeyParameter? privateKey = null;

            if (keyObject is AsymmetricCipherKeyPair keyPair)
                privateKey = keyPair.Private;
            else if (keyObject is AsymmetricKeyParameter keyParam && keyParam.IsPrivate)
                privateKey = keyParam;

            if (privateKey == null)
            {
                _logger.LogWarning("Invalid DKIM private key. Skipping signing.");
                return;
            }

            var headers = new HeaderId[] { HeaderId.From, HeaderId.Subject, HeaderId.Date, HeaderId.To };
            var signer = new DkimSigner(privateKey, domain, selector)
            {
                SignatureAlgorithm = DkimSignatureAlgorithm.RsaSha256,
                AgentOrUserIdentifier = "@" + domain
            };

            message.Prepare(EncodingConstraint.SevenBit);
            signer.Sign(message, headers);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to sign message with DKIM");
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