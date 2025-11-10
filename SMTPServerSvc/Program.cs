using Azure.Storage.Blobs;
using Azure.Data.Tables;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SmtpServer.Storage;
using SmtpServer.Authentication;
using SMTPServerSvc.Configuration;
using SMTPServerSvc.Services;

namespace SMTPServerSvc;

internal class Program
{
    static async Task Main(string[] args)
    {
        // Create Aspire application builder
        var builder = Host.CreateApplicationBuilder(args);

        // Add Aspire service defaults (telemetry, health checks, service discovery)
        builder.AddServiceDefaults();

        // Bind configuration
        var smtpConfig = builder.Configuration.GetSection(SmtpServerConfiguration.SectionName).Get<SmtpServerConfiguration>();
        builder.Services.AddSingleton(smtpConfig ?? new SmtpServerConfiguration());

        // Add Aspire Azure Storage integration - these will use the connection strings provided by Aspire
        builder.AddAzureBlobServiceClient("blobs");
        builder.AddAzureTableServiceClient("tables");

        // Register custom logger provider for Table Storage
        builder.Services.AddSingleton<TableStorageLoggerProvider>(provider =>
        {
            var tableServiceClient = provider.GetRequiredService<TableServiceClient>();
            return new TableStorageLoggerProvider(tableServiceClient);
        });

        // Register SMTP server components as SmtpServer interfaces
        // The SmtpServer library uses a service-based architecture where core functionality
        // is implemented through specific interfaces. We register both concrete implementations
        // and their corresponding interfaces to enable dependency injection.
        
        // Message Store: Handles the storage and retrieval of incoming email messages
        // SampleMessageStore implements IMessageStore to provide custom message handling logic
        // This could store messages in Azure Blob Storage, databases, or other persistence layers
        builder.Services.AddSingleton<SampleMessageStore>();
        builder.Services.AddSingleton<IMessageStore>(provider => provider.GetRequiredService<SampleMessageStore>());
        
        // Mailbox Filter: Controls which email addresses are allowed to receive messages
        // SampleMailboxFilter implements IMailboxFilter to validate recipient addresses
        // This provides security by rejecting emails to unauthorized recipients
        builder.Services.AddSingleton<SampleMailboxFilter>();
        builder.Services.AddSingleton<IMailboxFilter>(provider => provider.GetRequiredService<SampleMailboxFilter>());
        
        // User Authenticator: Handles SMTP authentication for clients sending emails
        // SampleUserAuthenticator implements IUserAuthenticator to verify user credentials
        // This ensures only authorized users can send emails through the SMTP server
        builder.Services.AddSingleton<SampleUserAuthenticator>();
        builder.Services.AddSingleton<IUserAuthenticator>(provider => provider.GetRequiredService<SampleUserAuthenticator>());

        // Register the hosted service
        builder.Services.AddHostedService<SmtpServerHostedService>();

        // Build the host
        var host = builder.Build();

        // Add custom table storage logging after the host is built
        var serviceProvider = host.Services;
        var loggerFactory = serviceProvider.GetRequiredService<ILoggerFactory>();
        var tableStorageProvider = serviceProvider.GetRequiredService<TableStorageLoggerProvider>();
        loggerFactory.AddProvider(tableStorageProvider);

        var logger = host.Services.GetRequiredService<ILogger<Program>>();
        
        try
        {
            logger.LogInformation("Starting SMTP Server Application with Aspire");
            logger.LogInformation("==========================================");
            logger.LogInformation("SMTP Server Configuration:");
            
            var config = host.Services.GetRequiredService<SmtpServerConfiguration>();
            logger.LogInformation("  Server Name: {ServerName}", config.ServerName);
            logger.LogInformation("  Ports: {Ports}", string.Join(", ", config.Ports));
            logger.LogInformation("  Allowed Recipient: {AllowedRecipient}", config.AllowedRecipient);
            logger.LogInformation("  Allowed Username: {AllowedUsername}", config.AllowedUsername);
            logger.LogInformation("  Blob Container: {BlobContainer}", config.BlobContainerName);
            logger.LogInformation("  Log Table: {LogTable}", config.LogTableName);
            logger.LogInformation("  Using Aspire-managed Azure Storage (Azurite in development)");
            logger.LogInformation("==========================================");

            await host.RunAsync();
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Application terminated unexpectedly");
            throw;
        }
        finally
        {
            logger.LogInformation("SMTP Server Application stopped");
        }
    }
}
