using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Azure.Storage.Blobs;
using Azure.Data.Tables;
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
    private readonly DefaultMessageStore _messageStore;
    private readonly DefaultMailboxFilter _mailboxFilter;
    private readonly DefaultUserAuthenticator _userAuthenticator;
    private readonly BlobServiceClient _blobServiceClient;
    private readonly TableServiceClient _tableServiceClient;
    private SmtpServer.SmtpServer? _smtpServer;

    public SmtpServerHostedService(
        ILogger<SmtpServerHostedService> logger,
        IServiceProvider serviceProvider,
        SmtpServerConfiguration configuration,
        DefaultMessageStore messageStore,
        DefaultMailboxFilter mailboxFilter,
        DefaultUserAuthenticator userAuthenticator,
        BlobServiceClient blobServiceClient,
        TableServiceClient tableServiceClient)
    {
        _logger = logger;
        _serviceProvider = serviceProvider;
        _configuration = configuration;
        _messageStore = messageStore;
        _mailboxFilter = mailboxFilter;
        _userAuthenticator = userAuthenticator;
        _blobServiceClient = blobServiceClient;
        _tableServiceClient = tableServiceClient;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Starting SMTP Server Hosted Service");

        try
        {
            // Ensure the SMTPSettings table exists and contains the current settings from appsettings.json
            await StartupStorageHelpers.EnsureSettingsTableAsync(_tableServiceClient, _configuration, _logger);
            await StartupStorageHelpers.TestBlobAsync(_blobServiceClient, "email-messages", _logger);
            await StartupStorageHelpers.TestTableAsync(_tableServiceClient, "SMTPServerLogs", _logger);
            await StartupStorageHelpers.TestTableAsync(_tableServiceClient, "spamlogs", _logger);

            // Configure SMTP server options using configuration
            var optionsBuilder = new SmtpServerOptionsBuilder()
                .ServerName(_configuration.ServerName);

            // Add configured ports
            foreach (var port in _configuration.Ports)
            {
                optionsBuilder.Endpoint(builder =>
                    builder
                        .Port(port, isSecure: false)
                        .AllowUnsecureAuthentication());
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