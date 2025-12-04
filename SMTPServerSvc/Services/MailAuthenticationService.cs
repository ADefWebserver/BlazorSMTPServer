using DnsClient;
using Microsoft.Extensions.Logging;
using Nager.EmailAuthentication;
using Nager.EmailAuthentication.FragmentParsers;
using Nager.EmailAuthentication.Models.Dmarc;
using Nager.EmailAuthentication.Models.Spf;
using Nager.EmailAuthentication.Models.Spf.Mechanisms;
using System.Linq;
using System.Net;

namespace SMTPServerSvc.Services;

public class MailAuthenticationService
{
    private readonly ILookupClient _dnsClient;
    private readonly ILogger<MailAuthenticationService> _logger;

    public MailAuthenticationService(ILogger<MailAuthenticationService> logger)
    {
        _logger = logger;
        _dnsClient = new LookupClient(); // Uses default DNS servers
    }

    /// <summary>
    /// Asynchronously validates whether the specified IP address is authorized to send email on behalf of the given domain
    /// according to the domain's SPF (Sender Policy Framework) record.
    /// </summary>
    /// <remarks>This method performs SPF validation by checking IP address matches, include mechanisms,
    /// and the 'all' mechanism. It recursively processes 'include:' directives to properly validate
    /// emails sent through third-party services like Gmail, Office 365, etc.</remarks>
    /// <param name="ipAddress">The IP address to validate against the domain's SPF record. This should be the address of the sending mail server.</param>
    /// <param name="domain">The domain name whose SPF record will be checked to determine if the specified IP address is permitted to send
    /// email.</param>
    /// <returns>A task that represents the asynchronous operation. The task result is <see langword="true"/> if the IP address is
    /// permitted by the domain's SPF record or if no SPF record is present; otherwise, <see langword="false"/>.</returns>
    #region public async Task<bool> ValidateSpfAsync(string ipAddress, string domain)
    public async Task<bool> ValidateSpfAsync(string ipAddress, string domain)
    {
        return await ValidateSpfAsync(ipAddress, domain, 0);
    }

    private async Task<bool> ValidateSpfAsync(string ipAddress, string domain, int depth)
    {
        // SPF spec limits DNS lookups to 10 to prevent infinite loops
        if (depth > 10)
        {
            _logger.LogWarning("SPF lookup limit exceeded for {Domain}", domain);
            return false;
        }

        try
        {
            // 1. Get TXT records for the domain
            var result = await _dnsClient.QueryAsync(domain, QueryType.TXT);

            // 2. Find the SPF record (starts with v=spf1)
            var spfRecordString = result.Answers.TxtRecords()
                .Select(r => string.Join("", r.Text)) // TXT records can be split into chunks
                .FirstOrDefault(s => s.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase));

            if (string.IsNullOrEmpty(spfRecordString))
            {
                _logger.LogInformation("No SPF record found for {Domain}", domain);
                return true; // No SPF record usually means "neutral" or "none", so we accept.
            }

            _logger.LogDebug("SPF record for {Domain}: {Record}", domain, spfRecordString);

            // 3. Parse with Nager.EmailAuthentication
            if (!SpfRecordDataFragmentParserV1.TryParse(spfRecordString, out var spfRecord))
            {
                _logger.LogWarning("Failed to parse SPF record for {Domain}: {Record}", domain, spfRecordString);
                return true;
            }

            // Parse the IP address once for comparisons
            if (!IPAddress.TryParse(ipAddress, out var senderIp))
            {
                _logger.LogWarning("Invalid IP address format: {IP}", ipAddress);
                return false;
            }

            // 4. Check mechanisms in order (order matters in SPF!)
            foreach (var term in spfRecord.SpfTerms)
            {
                // Check IPv4 mechanisms
                if (term is Ip4Mechanism ip4Mechanism)
                {
                    if (CheckIpMatch(senderIp, ip4Mechanism.MechanismData))
                    {
                        _logger.LogDebug("SPF Pass: IP {IP} matches ip4:{Mechanism} for {Domain}", ipAddress, ip4Mechanism.MechanismData, domain);
                        return true;
                    }
                }

                // Check IPv6 mechanisms
                if (term is Ip6Mechanism ip6Mechanism)
                {
                    if (CheckIpMatch(senderIp, ip6Mechanism.MechanismData))
                    {
                        _logger.LogDebug("SPF Pass: IP {IP} matches ip6:{Mechanism} for {Domain}", ipAddress, ip6Mechanism.MechanismData, domain);
                        return true;
                    }
                }

                // Check 'include:' mechanisms - THIS IS THE KEY FIX FOR GMAIL/GOOGLE
                if (term is IncludeMechanism includeMechanism && !string.IsNullOrEmpty(includeMechanism.MechanismData))
                {
                    var includeDomain = includeMechanism.MechanismData;
                    _logger.LogDebug("SPF checking include:{IncludeDomain} for {Domain}", includeDomain, domain);
                    
                    var includeResult = await ValidateSpfAsync(ipAddress, includeDomain, depth + 1);
                    if (includeResult)
                    {
                        _logger.LogDebug("SPF Pass: IP {IP} authorized via include:{IncludeDomain} for {Domain}", ipAddress, includeDomain, domain);
                        return true;
                    }
                }

                // Check 'a' mechanism (domain's A record)
                if (term is AMechanism aMechanism)
                {
                    var aDomain = string.IsNullOrEmpty(aMechanism.MechanismData) ? domain : aMechanism.MechanismData;
                    try
                    {
                        var aRecords = await _dnsClient.QueryAsync(aDomain, QueryType.A);
                        foreach (var aRecord in aRecords.Answers.ARecords())
                        {
                            if (aRecord.Address.Equals(senderIp))
                            {
                                _logger.LogDebug("SPF Pass: IP {IP} matches A record for {Domain}", ipAddress, aDomain);
                                return true;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Failed to check A record for {Domain}", aDomain);
                    }
                }

                // Check 'mx' mechanism (domain's MX record IPs)
                if (term is MxMechanism mxMechanism)
                {
                    var mxDomain = string.IsNullOrEmpty(mxMechanism.MechanismData) ? domain : mxMechanism.MechanismData;
                    try
                    {
                        var mxRecords = await _dnsClient.QueryAsync(mxDomain, QueryType.MX);
                        foreach (var mxRecord in mxRecords.Answers.MxRecords())
                        {
                            var mxHost = mxRecord.Exchange.Value.TrimEnd('.');
                            var mxARecords = await _dnsClient.QueryAsync(mxHost, QueryType.A);
                            foreach (var aRecord in mxARecords.Answers.ARecords())
                            {
                                if (aRecord.Address.Equals(senderIp))
                                {
                                    _logger.LogDebug("SPF Pass: IP {IP} matches MX record {MxHost} for {Domain}", ipAddress, mxHost, mxDomain);
                                    return true;
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Failed to check MX record for {Domain}", mxDomain);
                    }
                }

                // Handle 'all' mechanism (usually at the end)
                if (term is AllMechanism allMechanism)
                {
                    if (allMechanism.Qualifier == SpfQualifier.Pass)
                    {
                        _logger.LogDebug("SPF Pass: +all for {Domain}", domain);
                        return true;
                    }
                    if (allMechanism.Qualifier == SpfQualifier.Fail)
                    {
                        _logger.LogDebug("SPF Fail: -all for {Domain}, IP {IP} not authorized", domain, ipAddress);
                        return false;
                    }
                    if (allMechanism.Qualifier == SpfQualifier.SoftFail)
                    {
                        _logger.LogDebug("SPF SoftFail: ~all for {Domain}, treating as pass", domain);
                        return true; // ~all is usually accepted but tagged
                    }
                    if (allMechanism.Qualifier == SpfQualifier.Neutral)
                    {
                        _logger.LogDebug("SPF Neutral: ?all for {Domain}", domain);
                        return true;
                    }
                }
            }

            // If no mechanism matched and no 'all' with fail, we default to neutral (accept)
            _logger.LogDebug("SPF Neutral: No matching mechanism for {Domain}, IP {IP}", domain, ipAddress);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating SPF for {Domain}", domain);
            return true; // Fail open
        }
    }

    /// <summary>
    /// Checks if an IP address matches a mechanism data string (IP or CIDR notation).
    /// </summary>
    private bool CheckIpMatch(IPAddress senderIp, string? mechanismData)
    {
        if (string.IsNullOrEmpty(mechanismData)) return false;

        // Check for CIDR notation (e.g., "192.168.1.0/24")
        if (mechanismData.Contains('/'))
        {
            var parts = mechanismData.Split('/');
            if (parts.Length == 2 && IPAddress.TryParse(parts[0], out var networkIp) && int.TryParse(parts[1], out var prefixLength))
            {
                return IsInSubnet(senderIp, networkIp, prefixLength);
            }
        }

        // Direct IP comparison
        if (IPAddress.TryParse(mechanismData, out var mechanismIp))
        {
            return senderIp.Equals(mechanismIp);
        }

        return false;
    }

    /// <summary>
    /// Checks if an IP address is within a subnet defined by network address and prefix length.
    /// </summary>
    private bool IsInSubnet(IPAddress address, IPAddress networkAddress, int prefixLength)
    {
        if (address.AddressFamily != networkAddress.AddressFamily) return false;

        var addressBytes = address.GetAddressBytes();
        var networkBytes = networkAddress.GetAddressBytes();

        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;

        // Check full bytes
        for (int i = 0; i < fullBytes; i++)
        {
            if (addressBytes[i] != networkBytes[i]) return false;
        }

        // Check remaining bits if any
        if (remainingBits > 0 && fullBytes < addressBytes.Length)
        {
            int mask = 0xFF << (8 - remainingBits);
            if ((addressBytes[fullBytes] & mask) != (networkBytes[fullBytes] & mask)) return false;
        }

        return true;
    }
    #endregion

    /// <summary>
    /// Asynchronously retrieves the DMARC policy for the specified domain, if available.
    /// </summary>
    /// <remarks>This method queries the DNS for a DMARC TXT record associated with the specified domain. If no valid
    /// DMARC record is found or an error occurs during the lookup, the method returns null. The returned policy string
    /// corresponds to the 'p' tag in the DMARC record.</remarks>
    /// <param name="domain">The domain name for which to retrieve the DMARC policy. Cannot be null or empty.</param>
    /// <returns>A string representing the DMARC policy (such as "none", "quarantine", or "reject") if a valid DMARC record is found;
    /// otherwise, null.</returns>
    #region public async Task<string?> GetDmarcPolicyAsync(string domain)
    public async Task<string?> GetDmarcPolicyAsync(string domain)
    {
        try
        {
            var dmarcDomain = $"_dmarc.{domain}";
            var result = await _dnsClient.QueryAsync(dmarcDomain, QueryType.TXT);

            var dmarcRecordString = result.Answers.TxtRecords()
                .Select(r => string.Join("", r.Text))
                .FirstOrDefault(s => s.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase));

            if (string.IsNullOrEmpty(dmarcRecordString))
            {
                return null;
            }

            if (DmarcRecordParser.TryParse(dmarcRecordString, out var dmarcRecord) && dmarcRecord is DmarcRecordV1 dmarcV1)
            {
                return dmarcV1.DomainPolicy.ToString();
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching DMARC for {Domain}", domain);
            return null;
        }
    }
    #endregion

    /// <summary>
    /// Asynchronously validates the DKIM signature of an email message by performing full cryptographic verification.
    /// </summary>
    /// <remarks>This method performs complete DKIM validation including:
    /// - Fetching the public key from DNS
    /// - Verifying the cryptographic signature against the message headers and body
    /// - Checking canonicalization as specified in the signature</remarks>
    /// <param name="message">The MimeMessage to validate.</param>
    /// <returns>A task that represents the asynchronous operation. The task result is <see langword="true"/> if the DKIM signature
    /// is valid; otherwise, <see langword="false"/>.</returns>
    #region public async Task<bool> ValidateDkimAsync(MimeKit.MimeMessage message)
    public async Task<bool> ValidateDkimAsync(MimeKit.MimeMessage message)
    {
        try
        {
            // Check if message has DKIM signature
            var dkimHeader = message.Headers.FirstOrDefault(h => h.Id == MimeKit.HeaderId.DkimSignature);
            if (dkimHeader == null)
            {
                _logger.LogDebug("No DKIM-Signature header found in message");
                return false;
            }

            _logger.LogDebug("Found DKIM-Signature: {Signature}", dkimHeader.Value.Substring(0, Math.Min(100, dkimHeader.Value.Length)) + "...");

            // Use MimeKit's DkimVerifier for proper cryptographic validation
            var verifier = new MimeKit.Cryptography.DkimVerifier(new DkimPublicKeyLocator(_dnsClient, _logger));

            // Verify all DKIM signatures in the message
            var signatures = message.Headers.Where(h => h.Id == MimeKit.HeaderId.DkimSignature).ToList();
            
            foreach (var signature in signatures)
            {
                try
                {
                    bool isValid = await verifier.VerifyAsync(message, signature);
                    
                    if (isValid)
                    {
                        _logger.LogInformation("DKIM signature verified successfully");
                        return true;
                    }
                    else
                    {
                        _logger.LogWarning("DKIM signature verification failed");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error verifying DKIM signature: {Message}", ex.Message);
                }
            }

            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating DKIM");
            return false;
        }
    }
    #endregion

    /// <summary>
    /// Legacy method that only checks for DKIM public key existence (not full verification).
    /// </summary>
    [Obsolete("Use ValidateDkimAsync(MimeMessage) for proper cryptographic verification")]
    #region public async Task<bool> ValidateDkimAsync(string dkimSignatureHeader)
    public async Task<bool> ValidateDkimAsync(string dkimSignatureHeader)
    {
        try
        {
            var parts = dkimSignatureHeader.Split(';')
                .Select(p => p.Trim())
                .Where(p => !string.IsNullOrEmpty(p))
                .Select(p =>
                {
                    var idx = p.IndexOf('=');
                    if (idx == -1) return new { Key = p, Value = "" };
                    return new { Key = p.Substring(0, idx).Trim(), Value = p.Substring(idx + 1).Trim() };
                })
                .ToDictionary(x => x.Key, x => x.Value);

            if (!parts.TryGetValue("s", out var selector) || !parts.TryGetValue("d", out var domain))
            {
                _logger.LogWarning("DKIM signature missing selector or domain");
                return false;
            }

            var dkimDomain = $"{selector}._domainkey.{domain}";
            var result = await _dnsClient.QueryAsync(dkimDomain, QueryType.TXT);
            var dkimRecordString = result.Answers.TxtRecords()
                .Select(r => string.Join("", r.Text))
                .FirstOrDefault();

            if (string.IsNullOrEmpty(dkimRecordString))
            {
                _logger.LogWarning("No DKIM public key found for {DkimDomain}", dkimDomain);
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating DKIM");
            return false;
        }
    }
    #endregion
}

/// <summary>
/// DKIM public key locator that fetches keys from DNS for MimeKit's DkimVerifier.
/// </summary>
public class DkimPublicKeyLocator : MimeKit.Cryptography.IDkimPublicKeyLocator
{
    private readonly ILookupClient _dnsClient;
    private readonly ILogger _logger;

    public DkimPublicKeyLocator(ILookupClient dnsClient, ILogger logger)
    {
        _dnsClient = dnsClient;
        _logger = logger;
    }

    public Org.BouncyCastle.Crypto.AsymmetricKeyParameter? LocatePublicKey(string methods, string domain, string selector, CancellationToken cancellationToken = default)
    {
        return LocatePublicKeyAsync(methods, domain, selector, cancellationToken).GetAwaiter().GetResult();
    }

    public async Task<Org.BouncyCastle.Crypto.AsymmetricKeyParameter?> LocatePublicKeyAsync(string methods, string domain, string selector, CancellationToken cancellationToken = default)
    {
        var dkimDomain = $"{selector}._domainkey.{domain}";
        _logger.LogDebug("Looking up DKIM public key at {DkimDomain}", dkimDomain);

        try
        {
            var result = await _dnsClient.QueryAsync(dkimDomain, QueryType.TXT, cancellationToken: cancellationToken);
            var dkimRecordString = result.Answers.TxtRecords()
                .Select(r => string.Join("", r.Text))
                .FirstOrDefault();

            if (string.IsNullOrEmpty(dkimRecordString))
            {
                _logger.LogWarning("No DKIM public key found for {DkimDomain}", dkimDomain);
                return null;
            }

            _logger.LogDebug("Found DKIM record: {Record}", dkimRecordString);

            // Parse the DKIM record to extract the public key
            // Format: v=DKIM1; k=rsa; p=BASE64_PUBLIC_KEY
            var parts = dkimRecordString.Split(';')
                .Select(p => p.Trim())
                .Where(p => !string.IsNullOrEmpty(p))
                .Select(p =>
                {
                    var idx = p.IndexOf('=');
                    if (idx == -1) return new { Key = p.ToLowerInvariant(), Value = "" };
                    return new { Key = p.Substring(0, idx).Trim().ToLowerInvariant(), Value = p.Substring(idx + 1).Trim() };
                })
                .ToDictionary(x => x.Key, x => x.Value, StringComparer.OrdinalIgnoreCase);

            if (!parts.TryGetValue("p", out var publicKeyBase64) || string.IsNullOrEmpty(publicKeyBase64))
            {
                _logger.LogWarning("DKIM record missing public key (p=) for {DkimDomain}", dkimDomain);
                return null;
            }

            // Remove any whitespace from the base64 key
            publicKeyBase64 = publicKeyBase64.Replace(" ", "").Replace("\t", "").Replace("\r", "").Replace("\n", "");

            // Decode the public key
            var publicKeyBytes = Convert.FromBase64String(publicKeyBase64);

            // Parse the public key using BouncyCastle
            var keyParameter = Org.BouncyCastle.Security.PublicKeyFactory.CreateKey(publicKeyBytes);

            _logger.LogDebug("Successfully parsed DKIM public key for {DkimDomain}", dkimDomain);
            return keyParameter;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching DKIM public key for {DkimDomain}", dkimDomain);
            return null;
        }
    }
}
