using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using SmtpServer;
using SmtpServer.Mail;
using SmtpServer.Storage;
using SMTPServerSvc.Configuration;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace SMTPServerSvc.Services;

/// <summary>
/// Mailbox filter that checks Spamhaus for unauthenticated users and enforces recipient rules.
/// </summary>
public class SampleMailboxFilter : IMailboxFilter
{
    private readonly ILogger<SampleMailboxFilter> _logger;
    private readonly SmtpServerConfiguration _configuration;
    private readonly IDnsResolver _dnsResolver;
    private readonly HashSet<string> _allowedRecipients;
    private readonly IMemoryCache _cache;

    public SampleMailboxFilter(SmtpServerConfiguration configuration, ILogger<SampleMailboxFilter> logger, IDnsResolver dnsResolver, IMemoryCache cache)
    {
        _logger = logger;
        _configuration = configuration;
        _dnsResolver = dnsResolver;
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

        _logger.LogInformation("SampleMailboxFilter initialized. Allowed recipients: {Allowed}", string.Join(", ", _allowedRecipients));
    }

    public async Task<bool> CanAcceptFromAsync(ISessionContext context, IMailbox @from, int size, CancellationToken cancellationToken)
    {
        var fromAddress = @from.AsAddress();

        // Check if the user is authenticated (set by SampleUserAuthenticator)
        bool isAuthenticated = context.Properties.ContainsKey("IsAuthenticated") && (bool)context.Properties["IsAuthenticated"];

        if (isAuthenticated)
        {
            _logger.LogInformation("Accepting mail from authenticated user: {FromAddress}", fromAddress);
            return true;
        }

        if (context.Properties.TryGetValue("RemoteEndPoint", out var endpointObj) && endpointObj is IPEndPoint ipEndPoint)
        {
            var ipAddress = ipEndPoint.Address;
            // Only check IPv4 for Zen (IPv6 is supported but requires different handling/zones usually)
            if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                bool isListed = await CheckSpamhausAsync(ipAddress, _configuration.SpamhausKey);
                if (isListed)
                {
                    _logger.LogWarning("Detected spam from {FromAddress} (IP: {IP}) - Listed in Spamhaus. Tagging session as spam.", fromAddress, ipAddress);
                    // Tag the session as spam instead of rejecting
                    context.Properties["IsSpam"] = true;
                    return true;
                }
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

    private async Task<bool> CheckSpamhausAsync(IPAddress ip, string key)
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
            if (!string.IsNullOrWhiteSpace(key))
            {
                // Private key usage: reversed_ip.key.zen.dq.spamhaus.net
                var reversedIp = string.Join(".", ip.ToString().Split('.').Reverse());
                query = $"{reversedIp}.{key}.zen.dq.spamhaus.net";
            }
            else
            {
                // Public mirror usage: reversed_ip.zen.spamhaus.org
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
            // Not listed
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
}