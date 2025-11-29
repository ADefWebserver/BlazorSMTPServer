using Azure.Data.Tables;
using Azure.Storage.Blobs;
using DnsClient;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Logging;
using MimeKit;
using MimeKit.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using SmtpServer;
using SmtpServer.Protocol;
using SmtpServer.Storage;
using SMTPServerSvc.Configuration;
using System.Buffers;
using System.IO;
using System.Linq;
using System.Text;
using SmtpResponse = SmtpServer.Protocol.SmtpResponse;

namespace SMTPServerSvc.Services;

/// <summary>
/// Message store implementation that saves email messages to Azure Blob Storage and relays outgoing mail
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
    private readonly ILookupClient _lookupClient;
    private readonly string _containerName;
    private readonly bool _isAvailable;

    public DefaultMessageStore(
        BlobServiceClient blobServiceClient, 
        TableServiceClient tableServiceClient, 
        SmtpServerConfiguration configuration, 
        ILogger<DefaultMessageStore> logger, 
        MailAuthenticationService authService,
        ILookupClient lookupClient)
    {
        _blobServiceClient = blobServiceClient;
        _logger = logger;
        _configuration = configuration;
        _authService = authService;
        _lookupClient = lookupClient;
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

    /// <summary>
    /// Processes and saves an email message received during the SMTP session, relaying to remote recipients if
    /// necessary and storing locally addressed messages.
    /// </summary>
    /// <remarks>Messages addressed to local recipients are saved to storage if available; otherwise, their
    /// content is logged. Messages for remote recipients are relayed only if the session is authenticated. The method
    /// handles both local delivery and relaying within a single operation.</remarks>
    /// <param name="context">The session context for the current SMTP transaction. Provides authentication and session properties required
    /// for message processing.</param>
    /// <param name="transaction">The message transaction details, including sender and recipient information for the current SMTP message.</param>
    /// <param name="buffer">A read-only sequence of bytes containing the raw message data to be processed and saved.</param>
    /// <param name="cancellationToken">A cancellation token that can be used to cancel the asynchronous operation.</param>
    /// <returns>An <see cref="SmtpResponse"/> indicating the result of the save operation. Returns <see cref="SmtpResponse.Ok"/>
    /// if the message is successfully processed, <see cref="SmtpResponse.AuthenticationRequired"/> if authentication is
    /// required for relaying, or <see cref="SmtpResponse.TransactionFailed"/> if an error occurs.</returns>
    #region public override async Task<SmtpResponse> SaveAsync(ISessionContext context, IMessageTransaction transaction, ReadOnlySequence<byte> buffer, CancellationToken cancellationToken)
    public override async Task<SmtpResponse> SaveAsync(ISessionContext context, IMessageTransaction transaction, ReadOnlySequence<byte> buffer, CancellationToken cancellationToken)
    {
        try
        {
            // Log basic info
            var sessionId = context.Properties.ContainsKey("SessionId") ? context.Properties["SessionId"]?.ToString() ?? "unknown" : "unknown";
            var transactionId = transaction.GetHashCode().ToString();

            _logger.LogInformation("Processing message for session {SessionId}, transaction {TransactionId}, size {MessageSize} bytes.",
                sessionId, transactionId, buffer.Length);

            // Parse message
            using var stream = new MemoryStream(buffer.ToArray());
            var message = await MimeMessage.LoadAsync(stream, cancellationToken);

            // Identify recipients
            var localRecipients = new List<MailboxAddress>();
            var remoteRecipients = new List<MailboxAddress>();

            void Classify(IEnumerable<InternetAddress> addresses)
            {
                foreach (var addr in addresses.OfType<MailboxAddress>())
                {
                    // Determine if local or remote
                    bool isLocal = false;

                    // Check against configured domain or allowed recipient
                    if (!string.IsNullOrEmpty(_configuration.Domain))
                    {
                        // Compare domain
                        isLocal = string.Equals(addr.Domain, _configuration.Domain, StringComparison.OrdinalIgnoreCase);
                    } 
                    else if (!string.IsNullOrEmpty(_configuration.AllowedRecipient))
                    {
                        // Compare against allowed recipient's domain
                        var allowedDomain = _configuration.AllowedRecipient.Split('@').LastOrDefault();
                        isLocal = string.Equals(addr.Domain, allowedDomain, StringComparison.OrdinalIgnoreCase);
                    }

                    if (isLocal)
                    {
                        // Local recipient
                        localRecipients.Add(addr);
                    }
                    else
                    {
                        // Remote recipient
                        remoteRecipients.Add(addr);
                    }
                }
            }

            Classify(message.To);
            Classify(message.Cc);
            Classify(message.Bcc);

            // Handle Remote Recipients (Relay)
            if (remoteRecipients.Any())
            {
                // Check Authentication
                if (!context.Authentication.IsAuthenticated)
                {
                    _logger.LogWarning("Relay attempt denied: User not authenticated. Session: {SessionId}", sessionId);
                    return SmtpResponse.AuthenticationRequired;
                }

                _logger.LogInformation("Relaying message to {Count} remote recipients.", remoteRecipients.Count);

                // Relay
                await RelayMessageAsync(message, remoteRecipients, cancellationToken);
            }

            // Handle Local Recipients (Save to Blob)
            if (localRecipients.Any())
            {
                // Only proceed if storage is available
                if (!_isAvailable || _containerClient == null)
                {
                    _logger.LogWarning("Blob storage unavailable. Message content will be logged only.");
                    var logMessageContent = Encoding.UTF8.GetString(buffer.ToArray());
                    _logger.LogInformation("Message Content (Session {SessionId}):\n{MessageContent}", sessionId, logMessageContent);
                    return SmtpResponse.Ok;
                }

                // Save to Blob
                await SaveToBlobAsync(context, transaction, buffer, message, sessionId, transactionId, cancellationToken);
            }

            return SmtpResponse.Ok;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing message.");
            return SmtpResponse.TransactionFailed;
        }
    }
    #endregion

    /// <summary>
    /// Relays the specified email message to the given recipients by delivering it to their respective mail servers
    /// using SMTP.
    /// </summary>
    /// <remarks>The message is relayed directly to the recipients' mail servers, grouped by domain. If DKIM
    /// signing is enabled in the configuration, the message will be signed before delivery. If an MX record cannot be
    /// found for a recipient's domain, the method attempts to deliver to the domain's A record as a fallback. Errors
    /// encountered while relaying to individual domains are logged but do not stop the relay process for other
    /// domains.</remarks>
    /// <param name="message">The email message to be relayed. Must not be null.</param>
    /// <param name="recipients">A list of recipient mailbox addresses to which the message will be delivered. Must not be null or empty.</param>
    /// <param name="ct">A cancellation token that can be used to cancel the relay operation.</param>
    /// <returns>A task that represents the asynchronous relay operation.</returns>
    #region private async Task RelayMessageAsync(MimeMessage message, List<MailboxAddress> recipients, CancellationToken ct)
    private async Task RelayMessageAsync(MimeMessage message, List<MailboxAddress> recipients, CancellationToken ct)
    {
        // Sign DKIM if enabled
        if (_configuration.EnableDkimSigning &&
            !string.IsNullOrEmpty(_configuration.DkimDomain) &&
            !string.IsNullOrEmpty(_configuration.DkimSelector) &&
            !string.IsNullOrEmpty(_configuration.DkimPrivateKey))
        {
            _logger.LogInformation("Signing outgoing message with DKIM for domain {Domain}", _configuration.DkimDomain);
            SignMessage(message, _configuration.DkimDomain, _configuration.DkimSelector, _configuration.DkimPrivateKey);
        }

        var groups = recipients.GroupBy(r => r.Domain);
        foreach (var group in groups)
        {
            var domain = group.Key;
            try
            {
                _logger.LogInformation("Looking up MX records for {Domain}", domain);
                var mxRecords = await _lookupClient.QueryAsync(domain, QueryType.MX);
                var mxServer = mxRecords.Answers.MxRecords()
                    .OrderBy(mx => mx.Preference)
                    .Select(mx => mx.Exchange.Value)
                    .FirstOrDefault();

                if (string.IsNullOrEmpty(mxServer))
                {
                    mxServer = domain; // Fallback to A record
                }

                if (mxServer.EndsWith(".")) mxServer = mxServer.Substring(0, mxServer.Length - 1);

                _logger.LogInformation("Relaying to {Domain} via {MxServer}", domain, mxServer);

                using var client = new MailKit.Net.Smtp.SmtpClient();

                // Connect (Port 25 is standard for MTA-to-MTA)
                await client.ConnectAsync(mxServer, 25, MailKit.Security.SecureSocketOptions.Auto, ct);

                var sender = message.From.OfType<MailboxAddress>().FirstOrDefault() ?? new MailboxAddress("Sender", _configuration.AllowedRecipient);

                await client.SendAsync(message, sender, group, ct);
                await client.DisconnectAsync(true, ct);

                _logger.LogInformation("Successfully relayed message to {Domain}", domain);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to relay message to {Domain} - {ex}", domain, ex.Message);
            }
        }
    } 
    #endregion

    /// <summary>
    /// Saves the specified email message and its metadata to a blob storage container, organizing it by recipient and
    /// session information.
    /// </summary>
    /// <remarks>If the message is identified as spam, it is stored in a designated spam container or folder.
    /// Additional metadata, such as DKIM and DMARC validation results, session and transaction identifiers, and
    /// recipient information, are added as headers and blob metadata. The method also performs DKIM signing if enabled
    /// in the configuration or settings. This method logs relevant information and may trigger additional logging for
    /// spam messages.</remarks>
    /// <param name="context">The session context containing properties and state information relevant to the current SMTP session. Must not
    /// be null.</param>
    /// <param name="transaction">The message transaction representing the current SMTP transaction, including recipient and sender details. Must
    /// not be null.</param>
    /// <param name="buffer">A read-only sequence of bytes containing the raw message data to be saved.</param>
    /// <param name="message">The parsed MIME message to be stored in blob storage. Must not be null.</param>
    /// <param name="sessionId">The unique identifier for the current SMTP session. Used for organizing and tracking stored messages. Must not
    /// be null or empty.</param>
    /// <param name="transactionId">The unique identifier for the current message transaction. Used for metadata and tracking. Must not be null or
    /// empty.</param>
    /// <param name="cancellationToken">A cancellation token that can be used to cancel the asynchronous save operation.</param>
    /// <returns>A task that represents the asynchronous save operation.</returns>
    #region private async Task SaveToBlobAsync(ISessionContext context, IMessageTransaction transaction, ReadOnlySequence<byte> buffer, MimeMessage message, string sessionId, string transactionId, CancellationToken cancellationToken)
    private async Task SaveToBlobAsync(ISessionContext context, IMessageTransaction transaction, ReadOnlySequence<byte> buffer, MimeMessage message, string sessionId, string transactionId, CancellationToken cancellationToken)
    {
        // Check for spam tag
        bool isSpam = context.Properties.ContainsKey("IsSpam") && (bool)context.Properties["IsSpam"];

        // Get the correct container client
        var containerClient = isSpam ? _blobServiceClient!.GetBlobContainerClient(_containerName) : _containerClient!;
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

        string recipientFolder = SanitizeForBlobPath(recipientUser);
        if (isSpam) recipientFolder = "spam";

        var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd_HH-mm-ss-fff");
        var blobName = $"{timestamp}_{sessionId}_{Guid.NewGuid():N}.eml";
        var blobPath = $"{recipientFolder}/{blobName}";

        // Original content for metadata extraction
        var messageContent = Encoding.UTF8.GetString(buffer.ToArray());
        var originalSubject = message.Subject ?? "(no subject)";
        var originalFrom = message.From.ToString();

        // DKIM/DMARC Validation (Incoming)
        bool dkimPass = false;
        bool dmarcPass = false;

        // Re-implementing the manual extraction from original code for consistency
        static string? HeaderFromOriginal(string content, string key)
        {
            using var sr = new StringReader(content);
            string? l;
            var prefix = key + ":";
            while ((l = sr.ReadLine()) != null)
            {
                if (string.IsNullOrWhiteSpace(l)) break;
                if (l.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    return l.Substring(prefix.Length).Trim();
                }
            }
            return null;
        }
        string? dkimSignature = HeaderFromOriginal(messageContent, "DKIM-Signature");

        if (_configuration.EnableDkimCheck && !string.IsNullOrEmpty(dkimSignature))
        {
            dkimPass = await _authService.ValidateDkimAsync(dkimSignature);
        }

        if (_configuration.EnableDmarcCheck)
        {
            bool spfPass = context.Properties.ContainsKey("SpfPass") && (bool)context.Properties["SpfPass"];
            if (spfPass || dkimPass) dmarcPass = true;
        }

        // Add metadata headers to the message object
        message.Headers.Add("X-SMTP-Server-Received", DateTime.UtcNow.ToString("R"));
        message.Headers.Add("X-SMTP-Server-Session", sessionId);
        message.Headers.Add("X-SMTP-Server-Transaction", transactionId);
        message.Headers.Add("X-SMTP-Server-BlobName", blobPath);
        message.Headers.Add("X-SMTP-Server-Recipient-User", recipientUser);
        if (isSpam) message.Headers.Add("X-SMTP-Server-Spam", "True");
        if (dkimPass) message.Headers.Add("X-SMTP-Server-DKIM", "Pass");
        if (dmarcPass) message.Headers.Add("X-SMTP-Server-DMARC", "Pass");

        // DKIM Signing (for local storage - maybe we want to sign it too?)
        // Use configuration first, then table
        bool signed = false;
        if (_configuration.EnableDkimSigning && !string.IsNullOrEmpty(_configuration.DkimPrivateKey))
        {
            SignMessage(message, _configuration.DkimDomain, _configuration.DkimSelector, _configuration.DkimPrivateKey);
            signed = true;
        }

        if (!signed && _settingsTableClient != null)
        {
            // Fallback to table settings
            try
            {
                var settings = await _settingsTableClient.GetEntityIfExistsAsync<TableEntity>("SmtpServer", "Current");
                if (settings.HasValue && settings.Value != null)
                {
                    var enable = settings.Value.GetBoolean("EnableDkimSigning") ?? false;
                    var key = settings.Value.GetString("DkimPrivateKey");
                    var sel = settings.Value.GetString("DkimSelector");
                    var dom = settings.Value.GetString("DkimDomain");
                    if (enable && !string.IsNullOrEmpty(key))
                    {
                        SignMessage(message, dom, sel, key);
                    }
                }
            }
            catch { }
        }

        // Upload
        var blobClient = containerClient.GetBlobClient(blobPath);
        using var stream = new MemoryStream();
        await message.WriteToAsync(stream);
        stream.Position = 0;
        await blobClient.UploadAsync(stream, overwrite: true, cancellationToken);

        // Metadata
        var metadata = new Dictionary<string, string>
        {
            ["SessionId"] = sessionId,
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

        _logger.LogInformation("Message saved to blob {BlobPath}", blobPath);

        if (isSpam)
        {
            // Log spam
            string ipAddress = "unknown";
            if (context.Properties.TryGetValue("RemoteEndPoint", out var endpointObj) && endpointObj is System.Net.IPEndPoint ipEndPoint)
            {
                ipAddress = ipEndPoint.Address.ToString();
            }
            await LogSpamAsync(sessionId, transactionId, originalFrom, recipientUser, originalSubject, blobPath, ipAddress);
        }
    } 
    #endregion

    /// <summary>
    /// Asynchronously logs details of a detected spam message to the spam log storage.
    /// </summary>
    /// <remarks>If the spam log storage client is not configured, the method completes without logging.
    /// Errors encountered during logging are handled internally and do not propagate to the caller.</remarks>
    /// <param name="sessionId">The unique identifier for the current session in which the spam was detected.</param>
    /// <param name="transactionId">The unique identifier for the transaction associated with the spam message.</param>
    /// <param name="from">The email address of the sender of the spam message.</param>
    /// <param name="to">The email address of the intended recipient of the spam message.</param>
    /// <param name="subject">The subject line of the spam message.</param>
    /// <param name="blobPath">The storage path to the blob containing the spam message content.</param>
    /// <param name="ip">The IP address from which the spam message originated.</param>
    /// <returns>A task that represents the asynchronous logging operation.</returns>
    #region private async Task LogSpamAsync(string sessionId, string transactionId, string from, string to, string subject, string blobPath, string ip)
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
            _logger.LogError(ex, "Failed to log spam entry");
        }
    } 
    #endregion

    /// <summary>
    /// Signs the specified MIME message using DomainKeys Identified Mail (DKIM) with the provided domain, selector, and
    /// private key.
    /// </summary>
    /// <remarks>If the private key is invalid or signing fails, the message will not be signed and a warning
    /// will be logged. This method modifies the message in place by adding a DKIM-Signature header. Only the From,
    /// Subject, Date, and To headers are included in the signature. This method is not thread-safe if called
    /// concurrently on the same message instance.</remarks>
    /// <param name="message">The MIME message to sign. The message will be modified to include a DKIM-Signature header if signing succeeds.</param>
    /// <param name="domain">The domain name to use in the DKIM signature. This should match the domain of the sender.</param>
    /// <param name="selector">The DKIM selector that identifies the public key in DNS. Used to locate the DKIM public key record for
    /// verification.</param>
    /// <param name="privateKeyPem">The private key in PEM format used to generate the DKIM signature. Must be a valid RSA private key.</param>
    #region private void SignMessage(MimeMessage message, string domain, string selector, string privateKeyPem)
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
    #endregion

    /// <summary>
    /// Returns a sanitized version of the specified string that is safe for use as a blob storage path segment.
    /// </summary>
    /// <remarks>This method is useful for generating blob path segments that comply with common storage
    /// naming restrictions. Leading and trailing whitespace is removed from the result.</remarks>
    /// <param name="value">The input string to sanitize for use in a blob path. Can be null, empty, or contain any characters.</param>
    /// <returns>A string containing only letters, digits, periods (.), hyphens (-), and underscores (_), with all other
    /// characters replaced by underscores. Returns "unknown" if the input is null, empty, or consists only of
    /// whitespace or invalid characters.</returns>
    #region private static string SanitizeForBlobPath(string value)
    private static string SanitizeForBlobPath(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "unknown";
        var builder = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            if (char.IsLetterOrDigit(ch) || ch == '.' || ch == '-' || ch == '_') builder.Append(ch);
            else builder.Append('_');
        }
        var result = builder.ToString().Trim();
        return string.IsNullOrEmpty(result) ? "unknown" : result;
    } 
    #endregion
}
