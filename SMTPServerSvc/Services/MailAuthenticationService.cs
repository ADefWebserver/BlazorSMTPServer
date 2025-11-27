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
    /// Checks SPF for a given IP and Domain.
    /// </summary>
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

    public async Task<bool> ValidateDkimAsync(string dkimSignatureHeader)
    {
        try
        {
            // Manual parsing of DKIM-Signature header to extract selector (s=) and domain (d=)
            // Example: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; ...
            
            var parts = dkimSignatureHeader.Split(';')
                .Select(p => p.Trim())
                .Where(p => !string.IsNullOrEmpty(p))
                .Select(p => {
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
}
