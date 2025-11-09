using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SmtpServer;
using SMTPServerSvc.Services;

namespace SMTPServerSvc.Services;

/// <summary>
/// Hosted service that runs the SMTP server
/// </summary>
public class SmtpServerHostedService : BackgroundService
{
    private readonly ILogger<SmtpServerHostedService> _logger;
    private readonly IServiceProvider _serviceProvider;
    private readonly SampleMessageStore _messageStore;
    private readonly SampleMailboxFilter _mailboxFilter;
    private readonly SampleUserAuthenticator _userAuthenticator;
    private SmtpServer.SmtpServer? _smtpServer;

    public SmtpServerHostedService(
        ILogger<SmtpServerHostedService> logger,
        IServiceProvider serviceProvider,
        SampleMessageStore messageStore,
        SampleMailboxFilter mailboxFilter,
        SampleUserAuthenticator userAuthenticator)
    {
        _logger = logger;
        _serviceProvider = serviceProvider;
        _messageStore = messageStore;
        _mailboxFilter = mailboxFilter;
        _userAuthenticator = userAuthenticator;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Starting SMTP Server Hosted Service");

        try
        {
            // Configure SMTP server options
            var options = new SmtpServerOptionsBuilder()
                .ServerName("BlazorSMTPServer")
                .Port(25, 587) // Standard SMTP ports
                .Build();

            // Create SMTP server with service provider for dependency injection
            _smtpServer = new SmtpServer.SmtpServer(options, _serviceProvider);
            
            _logger.LogInformation("SMTP Server configured and starting on ports 25 and 587");
            _logger.LogInformation("Allowed recipient: TestUserOne@BlazorHelpWebsiteEmail.com");
            _logger.LogInformation("Allowed relay user: Admin");
            _logger.LogInformation("Messages will be stored in Azure Blob Storage");
            _logger.LogInformation("Logs will be written to Azure Table Storage");

            // Start the server
            await _smtpServer.StartAsync(stoppingToken);
            
            _logger.LogInformation("SMTP Server started successfully");

            // Keep the service running
            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(1000, stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("SMTP Server is stopping due to cancellation");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SMTP Server encountered an error");
            throw;
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Stopping SMTP Server");
        
        if (_smtpServer != null)
        {
            _smtpServer.Shutdown();
            _logger.LogInformation("SMTP Server stopped");
        }

        await base.StopAsync(cancellationToken);
    }
}