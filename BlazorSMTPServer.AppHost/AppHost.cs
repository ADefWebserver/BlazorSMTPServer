using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

var builder = DistributedApplication.CreateBuilder(args);

// Add Azurite storage emulator for development
// This will automatically start Azurite container or use local installation
var storage = builder.AddAzureStorage("storage")
    .RunAsEmulator();

// Add Blob storage resource
var blobs = storage.AddBlobs("blobs");

// Add Table storage resource  
var tables = storage.AddTables("tables");

// Add the Blazor web application
var blazorApp = builder.AddProject<Projects.BlazorSMTPServer>("blazorsmtpserver");

// Add the SMTP Server service with storage dependencies and expose SMTP ports
var smtpServer = builder.AddProject<Projects.SMTPServerSvc>("smtpserversvc")
    .WithReference(blobs)
    .WithReference(tables)
    .WithEndpoint("smtp-port1", endpoint =>
    {
        endpoint.Port = 2525;
        endpoint.IsExternal = true;
        endpoint.IsProxied = false; // Allow direct external access without proxy
    })
    .WithEndpoint("smtp-port2", endpoint =>
    {
        endpoint.Port = 587;
        endpoint.IsExternal = true;
        endpoint.IsProxied = false; // Allow direct external access without proxy
    });

// Optional: Add dependency so Blazor app can reference SMTP server if needed
blazorApp.WithReference(smtpServer);

builder.Build().Run();
