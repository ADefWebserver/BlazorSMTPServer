using System.Net;
using System.Net.Sockets;
using Azure.Data.Tables;
using SmtpServer;
using SmtpServer.Mail;
using SmtpServer.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using SMTPServerSvc.Configuration;

namespace SMTPServerSvc.Services;

public class DefaultMailboxFilter : IMailboxFilter
{
    private readonly ILogger<DefaultMailboxFilter> _logger;
    private readonly SmtpServerConfiguration _configuration;
    private readonly IDnsResolver _dnsResolver;
    private readonly MailAuthenticationService _authService;
    private readonly HashSet<string> _allowedRecipients;
    private readonly IMemoryCache _cache;
    private readonly TableClient? _spamLogTableClient;


    public DefaultMailboxFilter(SmtpServerConfiguration configuration, ILogger<DefaultMailboxFilter> logger, IDnsResolver dnsResolver, MailAuthenticationService authService, IMemoryCache cache, TableServiceClient tableServiceClient)
    {
        _logger = logger;
        _configuration = configuration;
        _dnsResolver = dnsResolver;
        _authService = authService;
        _cache = cache;
        _allowedRecipients = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var domain = configuration.ServerName?.Trim();
        var primaryLocal = configuration.AllowedRecipient?.Trim();

        if (!string.IsNullOrWhiteSpace(domain))
        {
            if (!string.IsNullOrWhiteSpace(primaryLocal))
            {
                _allowedRecipients.Add($"{primaryLocal}@{domain}");
            }
            // Always allow standard role accounts
            _allowedRecipients.Add($"abuse@{domain}");
            _allowedRecipients.Add($"postmaster@{domain}");
        }

        try
        {
            _spamLogTableClient = tableServiceClient.GetTableClient("spamlogs");
            _spamLogTableClient.CreateIfNotExists();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to initialize spam logs table client in DefaultMailboxFilter");
        }

        _logger.LogInformation("DefaultMailboxFilter initialized. Allowed recipients: {Allowed}", string.Join(", ", _allowedRecipients));
    }

    public async Task<bool> CanAcceptFromAsync(ISessionContext context, IMailbox @from, int size, CancellationToken cancellationToken)
    {
        var fromAddress = @from.AsAddress();

        // Check if the user is authenticated (set by DefaultUserAuthenticator)
        bool isAuthenticated = context.Properties.ContainsKey("IsAuthenticated") && (bool)context.Properties["IsAuthenticated"];

        if (isAuthenticated)
        {
            _logger.LogInformation("Accepting mail from authenticated user: {FromAddress}", fromAddress);
            return true;
        }

        // ******************************************************************************************************************************
        #region TEST HOOK: If the sender is "spam-test@spamhaus.org" (a special spam test address), force a check against the Spamhaus test IP
        if (string.Equals(fromAddress, "spam-test@spamhaus.org", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Detected SPAM TEST from {FromAddress}. Forcing check against 127.0.0.2", fromAddress);
            // 127.0.0.2 is the standard Spamhaus test IP that is always listed
            var testIp = IPAddress.Parse("127.0.0.2");
            bool isListed = await CheckSpamhausAsync(testIp);
            if (isListed)
            {
                _logger.LogWarning("Detected spam from {FromAddress} (TEST IP: {IP}) - Listed in Spamhaus. Tagging session as spam.", fromAddress, testIp);
                context.Properties["IsSpam"] = true;
                context.Properties["SpamIP"] = testIp.ToString();
                await LogSpamDetectionAsync(context, fromAddress, testIp.ToString());
                return true;
            }
        }
        #endregion
        // ******************************************************************************************************************************

        if (context.Properties.TryGetValue("EndpointListener:RemoteEndPoint", out var endpointObj) && endpointObj is IPEndPoint ipEndPoint)
        {
            var ipAddress = ipEndPoint.Address;
            // Only check IPv4 for Zen (IPv6 is supported but requires different handling/zones usually)
            if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                bool isListed = await CheckSpamhausAsync(ipAddress);
                if (isListed)
                {
                    _logger.LogWarning("Detected spam from {FromAddress} (IP: {IP}) - Listed in Spamhaus. Tagging session as spam.", fromAddress, ipAddress);
                    // Tag the session as spam instead of rejecting
                    context.Properties["IsSpam"] = true;
                    context.Properties["SpamIP"] = ipAddress.ToString();

                    await LogSpamDetectionAsync(context, fromAddress, ipAddress.ToString());

                    return true;
                }
            }

            // SPF Check
            if (_configuration.EnableSpfCheck)
            {
                var ip = ipAddress.ToString();
                var domain = @from.Host;
                bool spfPass = await _authService.ValidateSpfAsync(ip, domain);
                
                // Store SPF result for DMARC check later in MessageStore
                context.Properties["SpfPass"] = spfPass;
                context.Properties["FromDomain"] = domain;

                if (!spfPass)
                {
                    _logger.LogWarning("SPF Check Failed for {Domain} from IP {IP}", domain, ip);
                    context.Properties["IsSpam"] = true;
                    await LogSpamDetectionAsync(context, fromAddress, ip);
                }
            }

            // DMARC Check (Policy only at this stage)
            if (_configuration.EnableDmarcCheck)
            {
                var domain = @from.Host;
                var dmarcPolicy = await _authService.GetDmarcPolicyAsync(domain);
                if (!string.IsNullOrEmpty(dmarcPolicy))
                {
                    _logger.LogInformation("DMARC Policy for {Domain}: {Policy}", domain, dmarcPolicy);
                    // We cannot fully validate DMARC without DKIM (which requires body), 
                    // but we can log the policy presence.
                }
            }

            // DKIM Check (Not possible at MAIL FROM stage)
            if (_configuration.EnableDkimCheck)
            {
                // DKIM requires message body, so we cannot check it here.
                // This would typically be done in IMessageStore.SaveAsync
            }
        }

        _logger.LogInformation("Accepting mail from unauthenticated user: {FromAddress}", fromAddress);
        return true;
    }

    public Task<bool> CanDeliverToAsync(ISessionContext context, IMailbox to, IMailbox @from, CancellationToken cancellationToken)
    {
        var toAddress = to.AsAddress();
        var fromAddress = @from.AsAddress();

        _logger.LogInformation("Checking delivery to: {ToAddress} from: {FromAddress}", toAddress, fromAddress);

        // Check if the recipient is one of the allowed addresses (case-insensitive)
        var canDeliver = _allowedRecipients.Contains(toAddress);

        if (canDeliver)
        {
            _logger.LogInformation("Delivery allowed to: {ToAddress}", toAddress);
        }
        else
        {
            _logger.LogWarning("Delivery rejected to: {ToAddress}. Allowed recipients: {Allowed}", toAddress, string.Join(", ", _allowedRecipients));
        }

        return Task.FromResult(canDeliver);
    }

    private async Task<bool> CheckSpamhausAsync(IPAddress ip)
    {
        // Check cache first
        var cacheKey = $"spamcheck:{ip}";
        if (_cache.TryGetValue(cacheKey, out bool isListed))
        {
            return isListed;
        }

        try
        {
            string query;
            // Use private key if EnableSpamFiltering is true AND a key is provided
            if (_configuration.EnableSpamFiltering && !string.IsNullOrWhiteSpace(_configuration.SpamhausKey))
            {
                // Private key usage: reversed_ip.key.zen.dq.spamhaus.net
                query = BuildSpamhausQuery(ip, _configuration.SpamhausKey);
            }
            else
            {
                // Public mirror usage: reversed_ip.zen.spamhaus.org
                // This is used when EnableSpamFiltering is false OR no key is provided
                var reversedIp = string.Join(".", ip.ToString().Split('.').Reverse());
                query = $"{reversedIp}.zen.spamhaus.org";
            }

            _logger.LogDebug("Querying Spamhaus: {Query}", query);

            // If the host is found, it means the IP is listed.
            // If not found, Dns.GetHostAddressesAsync throws SocketException (HostNotFound).
            var addresses = await _dnsResolver.GetHostAddressesAsync(query);

            if (addresses.Length > 0)
            {
                // Any return value (typically 127.0.0.x) means it is listed.
                _logger.LogInformation("Spamhaus hit for IP {IP}: {ResultCodes}", ip, string.Join(",", (IEnumerable<IPAddress>)addresses));

                // Cache positive result for 1 hour
                _cache.Set(cacheKey, true, TimeSpan.FromHours(1));
                return true;
            }
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.HostNotFound)
        {
            // Host Not listed
            // Cache negative result for 15 minutes
            _cache.Set(cacheKey, false, TimeSpan.FromMinutes(15));
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking Spamhaus for IP {IP}", ip);
            // Fail open (allow) if DNS check fails to avoid blocking legitimate mail on errors
            // Do not cache errors
        }

        return false;
    }

    public string BuildSpamhausQuery(IPAddress ip, string licenseKey)
    {
        // 1. Check if the IP is IPv4
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            // Handle IPv6 or throw exception depending on your needs
            // Spamhaus supports IPv6, but the reversal logic is completely different.
            throw new NotSupportedException("This implementation only supports IPv4.");
        }

        // 2. Efficiently reverse the bytes without string splitting overhead
        var bytes = ip.GetAddressBytes();
        
        // 3. Create the string (192.168.1.1 -> 1.1.168.192)
        var reversedIp = string.Join(".", bytes.Reverse());

        // 4. Construct the DQS query
        return $"{reversedIp}.{licenseKey}.zen.dq.spamhaus.net";
    }

    private async Task LogSpamDetectionAsync(ISessionContext context, string from, string ip)
    {
        if (_spamLogTableClient == null) return;

        try
        {
            var sessionId = context.Properties.ContainsKey("SessionId") ? context.Properties["SessionId"]?.ToString() ?? "unknown" : "unknown";

            var entity = new TableEntity
            {
                PartitionKey = DateTime.UtcNow.ToString("yyyy-MM-dd"),
                RowKey = $"{DateTime.UtcNow:HHmmss.fff}_{Guid.NewGuid():N}_DETECT",
                ["Timestamp"] = DateTime.UtcNow,
                ["SessionId"] = sessionId,
                ["TransactionId"] = "detection", // No transaction ID yet at this stage usually
                ["From"] = from,
                ["To"] = "unknown", // Recipient not known at MAIL FROM stage usually, or not relevant for connection block
                ["Subject"] = "(spam detected during connection/mailfrom)",
                ["BlobPath"] = "not-saved",
                ["IP"] = ip,
                ["Status"] = "Detected"
            };

            await _spamLogTableClient.AddEntityAsync(entity);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to log spam detection to table storage");
        }
    }
}