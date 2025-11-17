using Microsoft.Extensions.Logging;
using SmtpServer;
using SmtpServer.Mail;
using SmtpServer.Storage;
using SMTPServerSvc.Configuration;
using System.Collections.Generic;

namespace SMTPServerSvc.Services;

/// <summary>
/// Mailbox filter that only allows emails to be received for the configured allowed recipient
/// plus standard role accounts like 'abuse' and 'postmaster'.
/// </summary>
public class SampleMailboxFilter : IMailboxFilter
{
    private readonly ILogger<SampleMailboxFilter> _logger;
    private readonly HashSet<string> _allowedRecipients;

    public SampleMailboxFilter(SmtpServerConfiguration configuration, ILogger<SampleMailboxFilter> logger)
    {
        _logger = logger;
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

    public Task<bool> CanAcceptFromAsync(ISessionContext context, IMailbox @from, int size, CancellationToken cancellationToken)
    {
        var fromAddress = @from.AsAddress();
        _logger.LogInformation("Checking if can accept mail from: {FromAddress}, size: {Size} bytes", fromAddress, size);
        
        // Allow any sender for now, but log it
        _logger.LogInformation("Accepting mail from: {FromAddress}", fromAddress);
        return Task.FromResult(true);
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
}