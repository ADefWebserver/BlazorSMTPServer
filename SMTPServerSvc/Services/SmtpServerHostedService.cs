using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SmtpServer;
using SMTPServerSvc.Services;
using SMTPServerSvc.Configuration;

namespace SMTPServerSvc.Services;

/// <summary>
/// Hosted service that runs the SMTP server
/// </summary>
public class SmtpServerHostedService : BackgroundService
{
    private readonly ILogger<SmtpServerHostedService> _logger;
    private readonly IServiceProvider _serviceProvider;
    private readonly SmtpServerConfiguration _configuration;
    private readonly SampleMessageStore _messageStore;
    private readonly SampleMailboxFilter _mailboxFilter;
    private readonly SampleUserAuthenticator _userAuthenticator;
    private SmtpServer.SmtpServer? _smtpServer;

    public SmtpServerHostedService(
        ILogger<SmtpServerHostedService> logger,
        IServiceProvider serviceProvider,
        SmtpServerConfiguration configuration,
        SampleMessageStore messageStore,
        SampleMailboxFilter mailboxFilter,
        SampleUserAuthenticator userAuthenticator)
    {
        _logger = logger;
        _serviceProvider = serviceProvider;
        _configuration = configuration;
        _messageStore = messageStore;
        _mailboxFilter = mailboxFilter;
        _userAuthenticator = userAuthenticator;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Starting SMTP Server Hosted Service");

        try
        {
            // Configure SMTP server options using configuration
            var optionsBuilder = new SmtpServerOptionsBuilder()
                .ServerName(_configuration.ServerName);

            // Add configured ports
            foreach (var port in _configuration.Ports)
            {
                optionsBuilder.Port(port);
            }

            var options = optionsBuilder.Build();

            // Create SMTP server with service provider for dependency injection
            _smtpServer = new SmtpServer.SmtpServer(options, _serviceProvider);
            
            _logger.LogInformation("SMTP Server configured and starting on ports {Ports}", string.Join(", ", _configuration.Ports));
            _logger.LogInformation("Server Name: {ServerName}", _configuration.ServerName);
            _logger.LogInformation("Allowed recipient: {AllowedRecipient}", _configuration.AllowedRecipient);
            _logger.LogInformation("Allowed relay user: {AllowedUsername}", _configuration.AllowedUsername);
            _logger.LogInformation("Messages will be stored in Azure Blob Storage container: {BlobContainer}", "email-messages");
            _logger.LogInformation("Logs will be written to Azure Table Storage table: {LogTable}", "SMTPServerLogs");

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