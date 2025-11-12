using Microsoft.Extensions.Logging;
using SmtpServer;
using SmtpServer.Mail;
using SmtpServer.Storage;
using SMTPServerSvc.Configuration;

namespace SMTPServerSvc.Services;

/// <summary>
/// Mailbox filter that only allows emails to be received for the configured allowed recipient
/// </summary>
public class SampleMailboxFilter : IMailboxFilter
{
    private readonly ILogger<SampleMailboxFilter> _logger;
    private readonly string _allowedRecipient;

    public SampleMailboxFilter(SmtpServerConfiguration configuration, ILogger<SampleMailboxFilter> logger)
    {
        _logger = logger;
        _allowedRecipient = configuration.AllowedRecipient;
        
        _logger.LogInformation("SampleMailboxFilter initialized. Only allowing emails to: {AllowedRecipient}", _allowedRecipient);
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

        // Check if the recipient matches our allowed address (case-insensitive)
        var canDeliver = string.Equals(toAddress, _allowedRecipient, StringComparison.OrdinalIgnoreCase);
        
        if (canDeliver)
        {
            _logger.LogInformation("Delivery allowed to: {ToAddress}", toAddress);
        }
        else
        {
            _logger.LogWarning("Delivery rejected to: {ToAddress}. Only {AllowedRecipient} is allowed", toAddress, _allowedRecipient);
        }

        return Task.FromResult(canDeliver);
    }
}