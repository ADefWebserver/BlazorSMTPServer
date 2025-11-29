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
    /// <remarks>This method performs a simplified SPF validation by checking for explicit IP address matches and
    /// evaluating the 'all' mechanism in the SPF record. It does not process all possible SPF mechanisms, such as includes
    /// or redirects. If the SPF record cannot be retrieved or parsed, or if no SPF record exists, the method returns <see
    /// langword="true"/> (accepts the sender).</remarks>
    /// <param name="ipAddress">The IP address to validate against the domain's SPF record. This should be the address of the sending mail server.</param>
    /// <param name="domain">The domain name whose SPF record will be checked to determine if the specified IP address is permitted to send
    /// email.</param>
    /// <returns>A task that represents the asynchronous operation. The task result is <see langword="true"/> if the IP address is
    /// permitted by the domain's SPF record or if no SPF record is present; otherwise, <see langword="false"/>.</returns>
    #region public async Task<bool> ValidateSpfAsync(string ipAddress, string domain)
    public async Task<bool> ValidateSpfAsync(string ipAddress, string domain)
    {
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

            // 3. Parse with Nager.EmailAuthentication
            if (!SpfRecordDataFragmentParserV1.TryParse(spfRecordString, out var spfRecord))
            {
                _logger.LogWarning("Failed to parse SPF record for {Domain}: {Record}", domain, spfRecordString);
                return true;
            }

            // 4. Check mechanisms
            // This is a simplified check. A full SPF check is complex (includes, redirects, etc.)
            // We will check for explicit IP matches.

            // Check IPv4
            foreach (var mechanism in spfRecord.SpfTerms.OfType<Ip4Mechanism>())
            {
                if (mechanism.MechanismData == ipAddress) return true; // Pass
                // TODO: Handle CIDR ranges if needed, but exact match is a good start
            }

            // Check IPv6
            foreach (var mechanism in spfRecord.SpfTerms.OfType<Ip6Mechanism>())
            {
                if (mechanism.MechanismData == ipAddress) return true; // Pass
            }

            // Handle 'all' mechanism (usually at the end)
            var allMechanism = spfRecord.SpfTerms.OfType<AllMechanism>().FirstOrDefault();
            if (allMechanism != null)
            {
                if (allMechanism.Qualifier == SpfQualifier.Fail) return false; // -all
                if (allMechanism.Qualifier == SpfQualifier.SoftFail) return true; // ~all (usually accepted but tagged)
            }

            // If no mechanism matched and no 'all' with fail, we default to accept?
            // Strictly speaking, if it falls through, it's Neutral.
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating SPF for {Domain}", domain);
            return true; // Fail open
        }
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
    /// Asynchronously checks whether a DKIM public key exists for the specified DKIM-Signature header.
    /// </summary>
    /// <remarks>This method only verifies the presence of a DKIM public key for the given selector and
    /// domain. It does not perform full cryptographic validation of the DKIM signature.</remarks>
    /// <param name="dkimSignatureHeader">The value of the DKIM-Signature header to validate. Must include the selector (s=) and domain (d=) tags.</param>
    /// <returns>A task that represents the asynchronous operation. The task result is <see langword="true"/> if a corresponding
    /// DKIM public key is found; otherwise, <see langword="false"/>.</returns>
    #region public async Task<bool> ValidateDkimAsync(string dkimSignatureHeader)
    public async Task<bool> ValidateDkimAsync(string dkimSignatureHeader)
    {
        try
        {
            // Manual parsing of DKIM-Signature header to extract selector (s=) and domain (d=)
            // Example: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; ...

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

            // Fetch Public Key
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

            // We found the key. 
            // NOTE: This only verifies the public key exists. 
            // Full cryptographic verification requires hashing the body and headers, which is complex.
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
