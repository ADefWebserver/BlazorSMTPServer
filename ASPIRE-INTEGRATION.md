# .NET Aspire Integration for SMTP Server

This document describes the .NET Aspire integration added to the BlazorSMTPServer solution.

## Overview

The solution now includes .NET Aspire 9.5.2 integration, providing:

- **Orchestrated Development**: Both Blazor app and SMTP server run together
- **Azurite Integration**: Automatic Azure Storage emulator management
- **Service Discovery**: Services can communicate through Aspire
- **Observability**: Built-in telemetry, logging, and health checks
- **Configuration Management**: Centralized connection string management

## Architecture

```
BlazorSMTPServer.AppHost (Orchestrator)
??? BlazorSMTPServer (Blazor Web App)
??? SMTPServerSvc (SMTP Server Service)
??? Azurite Storage Emulator
?   ??? Blob Storage (email-messages container)
?   ??? Table Storage (SMTPServerLogs table)
```

## Getting Started with Aspire

### Prerequisites

1. **.NET 9.0 SDK**
2. **Visual Studio 2022 17.8+** or **Visual Studio Code** with C# extension
3. **Docker Desktop** (for Azurite container)

### Running the Solution

#### Option 1: Visual Studio (Recommended)

1. Open `BlazorSMTPServer.sln` in Visual Studio
2. Set `BlazorSMTPServer.AppHost` as the startup project
3. Press F5 or click "Start"

This will:
- Start the Aspire Dashboard
- Launch Azurite storage emulator
- Start the Blazor web application
- Start the SMTP server service
- Open the Aspire dashboard in your browser

#### Option 2: Command Line

```bash
# Navigate to the AppHost project
cd BlazorSMTPServer.AppHost

# Run the Aspire application
dotnet run
```

#### Option 3: Using .NET Aspire CLI

```bash
# Install Aspire workload if not already installed
dotnet workload update
dotnet workload install aspire

# Run the application
dotnet run --project BlazorSMTPServer.AppHost
```

### Aspire Dashboard

The Aspire dashboard provides:

- **Resources**: View all running services and their status
- **Console Logs**: Real-time logs from all services
- **Traces**: Distributed tracing across services
- **Metrics**: Performance metrics and health checks
- **Environment**: Configuration and environment variables

Access the dashboard at: `https://localhost:15888` (default)

## Aspire Configuration

### AppHost Configuration

The `BlazorSMTPServer.AppHost/AppHost.cs` file configures:

```csharp
// Add Azurite storage emulator
var storage = builder.AddAzureStorage("storage").RunAsEmulator();

// Add storage resources
var blobs = storage.AddBlobs("blobs");
var tables = storage.AddTables("tables");

// Add projects with dependencies
var blazorApp = builder.AddProject<Projects.BlazorSMTPServer>("blazorsmtpserver");
var smtpServer = builder.AddProject<Projects.SMTPServerSvc>("smtpserversvc")
    .WithReference(blobs)
    .WithReference(tables);
```

### Service Configuration

The SMTPServerSvc now uses Aspire service defaults:

```csharp
// Add Aspire service defaults
builder.AddServiceDefaults();

// Add Azure storage clients (managed by Aspire)
builder.AddAzureBlobClient("blobs");
builder.AddAzureTableClient("tables");
```

### Connection Strings

Aspire automatically manages connection strings. In development, these are set to use Azurite:

```json
{
  "ConnectionStrings": {
    "blobs": "UseDevelopmentStorage=true",
    "tables": "UseDevelopmentStorage=true"
  }
}
```

## Storage Resources

### Azurite Emulator

Aspire automatically:
- Starts Azurite in a Docker container
- Creates necessary containers and tables
- Manages connection strings
- Provides health checks

### Blob Storage

- **Container**: `email-messages` (or `email-messages-dev` in development)
- **Purpose**: Stores email messages as `.eml` files
- **Managed by**: Aspire-injected `BlobServiceClient`

### Table Storage

- **Table**: `SMTPServerLogs` (or `SMTPServerLogsDev` in development)
- **Purpose**: Stores application logs and SMTP operation traces
- **Managed by**: Aspire-injected `TableServiceClient`

## Benefits of Aspire Integration

### Development Experience

1. **Single Command Start**: Start entire solution with one command
2. **Unified Logging**: All service logs in one dashboard  
3. **Resource Management**: Automatic Azurite lifecycle management
4. **Service Discovery**: Services can find each other automatically

### Observability

1. **Distributed Tracing**: Track requests across services
2. **Metrics Collection**: Automatic performance metrics
3. **Health Checks**: Built-in health monitoring
4. **Structured Logging**: Consistent logging across services

### Production Readiness

1. **Configuration Management**: Environment-specific settings
2. **Service Communication**: Secure inter-service communication
3. **Scaling**: Ready for container orchestration
4. **Monitoring**: Built-in OpenTelemetry integration

## Testing the Integration

### Verify Aspire is Working

1. Start the solution with Aspire
2. Open the Aspire dashboard
3. Verify all services are running (green status)
4. Check that Azurite storage is healthy

### Test SMTP Functionality

1. Navigate to the Blazor web app
2. Send a test email to `TestUserOne@BlazorHelpWebsiteEmail.com`
3. Check the Aspire dashboard for logs and traces
4. Verify email is stored in blob storage
5. Verify logs are written to table storage

### Monitor with Aspire Dashboard

1. **Resources Tab**: See all running services
2. **Console Logs Tab**: Real-time log streaming
3. **Traces Tab**: Distributed trace visualization
4. **Metrics Tab**: Performance dashboards

## Production Deployment

For production deployment, update connection strings to point to actual Azure Storage:

```json
{
  "ConnectionStrings": {
    "blobs": "DefaultEndpointsProtocol=https;AccountName=youraccount;AccountKey=yourkey;EndpointSuffix=core.windows.net",
    "tables": "DefaultEndpointsProtocol=https;AccountName=youraccount;AccountKey=yourkey;EndpointSuffix=core.windows.net"
  }
}
```

Or use managed identity in Azure:

```csharp
// In production, this would use managed identity automatically
builder.AddAzureBlobClient("blobs");
builder.AddAzureTableClient("tables");
```

## Troubleshooting

### Common Issues

1. **Docker not running**: Ensure Docker Desktop is running for Azurite
2. **Port conflicts**: Check that ports 15888 (dashboard) and 10000-10002 (Azurite) are available
3. **Service not starting**: Check console logs in Aspire dashboard

### Debugging

1. Use Aspire dashboard console logs for real-time debugging
2. Enable debug logging in `appsettings.Development.json`
3. Use distributed tracing to track request flows

### Health Checks

Aspire automatically provides health checks for:
- SMTP Server service
- Blob storage connectivity
- Table storage connectivity
- Overall application health

## Next Steps

1. **Add Blazor Integration**: Connect Blazor app to SMTP server for email management UI
2. **Add Authentication**: Integrate with Azure AD for secure access
3. **Add Monitoring**: Set up Application Insights for production monitoring
4. **Add CI/CD**: Deploy to Azure Container Apps using Aspire

## Resources

- [.NET Aspire Documentation](https://learn.microsoft.com/en-us/dotnet/aspire/)
- [Azure Storage with Aspire](https://learn.microsoft.com/en-us/dotnet/aspire/storage/azure-storage)
- [Aspire Dashboard Guide](https://learn.microsoft.com/en-us/dotnet/aspire/fundamentals/dashboard)