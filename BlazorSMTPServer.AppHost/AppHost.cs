var builder = DistributedApplication.CreateBuilder(args);

// Add Azurite storage emulator for development
var storage = builder.AddAzureStorage("storage")
    .RunAsEmulator(); // This will use Azurite

// Add Blob storage resource
var blobs = storage.AddBlobs("blobs");

// Add Table storage resource  
var tables = storage.AddTables("tables");

// Add the Blazor web application
var blazorApp = builder.AddProject<Projects.BlazorSMTPServer>("blazorsmtpserver");

// Add the SMTP Server service with storage dependencies
var smtpServer = builder.AddProject<Projects.SMTPServerSvc>("smtpserversvc")
    .WithReference(blobs)
    .WithReference(tables);

// Optional: Add dependency so Blazor app can reference SMTP server if needed
blazorApp.WithReference(smtpServer);

builder.Build().Run();
