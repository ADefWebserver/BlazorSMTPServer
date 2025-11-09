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
        builder.AddAzureBlobClient("blobs");
        builder.AddAzureTableClient("tables");

        // Register custom logger provider for Table Storage
        builder.Services.AddSingleton<TableStorageLoggerProvider>(provider =>
        {
            var tableServiceClient = provider.GetRequiredService<TableServiceClient>();
            return new TableStorageLoggerProvider(tableServiceClient);
        });

        // Register SMTP server components as SmtpServer interfaces
        builder.Services.AddSingleton<SampleMessageStore>();
        builder.Services.AddSingleton<IMessageStore>(provider => provider.GetRequiredService<SampleMessageStore>());
        
        builder.Services.AddSingleton<SampleMailboxFilter>();
        builder.Services.AddSingleton<IMailboxFilter>(provider => provider.GetRequiredService<SampleMailboxFilter>());
        
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
