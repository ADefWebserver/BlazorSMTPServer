# SMTP Server Service

A comprehensive SMTP server implementation using the SmtpServer library with Azure Storage integration for message storage and logging.

## Features

- **SMTP Server**: Fully functional SMTP server supporting standard ports (25, 587)
- **Azure Blob Storage**: Stores all received email messages as `.eml` files
- **Azure Table Storage**: Comprehensive logging of all SMTP operations
- **Mailbox Filtering**: Only accepts emails for `TestUserOne@BlazorHelpWebsiteEmail.com`
- **Authentication**: SMTP relay authentication for user `Admin` with password `password`
- **Comprehensive Logging**: All operations logged to both console and Azure Table Storage
- **Development Helper**: PowerShell script for easy development and testing

## Prerequisites

1. **.NET 9.0** - The application targets .NET 9.0
2. **Node.js** - Required for Azurite
3. **Azurite** (for development) - Azure Storage Emulator
   ```bash
   npm install -g azurite
   ```
4. **Azure Storage Account** (for production)

## Quick Start

### Using the Development Helper Script (Recommended)

1. **Start Azurite**:
   ```powershell
   .\dev-helper.ps1 start-azurite
   ```

2. **Run the SMTP server** (in a new terminal):
   ```powershell
   .\dev-helper.ps1 run-server
   ```

3. **Test the server** (in another terminal):
   ```powershell
   .\dev-helper.ps1 test-server
   ```

### Manual Setup

1. **Start Azurite** (Azure Storage Emulator):
   ```bash
   azurite --silent --location c:\azurite --debug c:\azurite\debug.log
   ```

2. **Run the application**:
   ```bash
   cd SMTPServerSvc
   dotnet run
   ```

The application will use the default Azurite connection string `UseDevelopmentStorage=true`.

## Configuration

The application supports the following configuration options in `appsettings.json`:

```json
{
  "SmtpServer": {
    "StorageConnectionString": "UseDevelopmentStorage=true",
    "ServerName": "BlazorSMTPServer",
    "Ports": [25, 587],
    "AllowedRecipient": "TestUserOne@BlazorHelpWebsiteEmail.com",
    "AllowedUsername": "Admin",
    "AllowedPassword": "password",
    "BlobContainerName": "email-messages",
    "LogTableName": "SMTPServerLogs"
  }
}
```

### Development vs Production Configuration

- **Development** (`appsettings.Development.json`): Uses ports 2525, 2587 and dev containers
- **Production** (`appsettings.json`): Uses standard ports 25, 587

### Production Environment

1. **Update configuration** in `appsettings.json` or use environment variables:
   ```json
   {
     "SmtpServer": {
       "StorageConnectionString": "DefaultEndpointsProtocol=https;AccountName=your-account;AccountKey=your-key;EndpointSuffix=core.windows.net"
     }
   }
   ```

2. **Environment Variables**:
   ```bash
   SmtpServer__StorageConnectionString="your-azure-storage-connection-string"
   ```

## Usage

### Sending Email to the Server

You can test the SMTP server using any SMTP client or telnet:

#### Using the Helper Script
```powershell
.\dev-helper.ps1 test-server
```

#### Using Telnet (Basic Test)
```bash
telnet localhost 2525
HELO test.com
MAIL FROM: sender@example.com
RCPT TO: TestUserOne@BlazorHelpWebsiteEmail.com
DATA
Subject: Test Email

This is a test email.
.
QUIT
```

#### Using PowerShell
```powershell
$smtp = New-Object System.Net.Mail.SmtpClient("localhost", 2525)
$smtp.Credentials = New-Object System.Net.NetworkCredential("Admin", "password")
$smtp.EnableSsl = $false

$mail = New-Object System.Net.Mail.MailMessage
$mail.From = "sender@example.com"
$mail.To.Add("TestUserOne@BlazorHelpWebsiteEmail.com")
$mail.Subject = "Test from PowerShell"
$mail.Body = "This is a test email sent from PowerShell"

$smtp.Send($mail)
```

#### Using C# Code
```csharp
using System.Net.Mail;
using System.Net;

var client = new SmtpClient("localhost", 2525)
{
    Credentials = new NetworkCredential("Admin", "password"),
    EnableSsl = false
};

var message = new MailMessage
{
    From = new MailAddress("sender@example.com"),
    Subject = "Test Email",
    Body = "This is a test email from C#"
};

message.To.Add("TestUserOne@BlazorHelpWebsiteEmail.com");

await client.SendMailAsync(message);
```

## Storage Structure

### Azure Blob Storage
- **Container**: `email-messages` (or configured container name)
- **File Format**: `yyyy-MM-dd_HH-mm-ss-fff_sessionId_guid.eml`
- **Content**: Standard EML format with additional headers:
  - `X-SMTP-Server-Received`: Timestamp
  - `X-SMTP-Server-Session`: Session ID
  - `X-SMTP-Server-Transaction`: Transaction ID

### Azure Table Storage
- **Table**: `SMTPServerLogs` (or configured table name)
- **Partition Key**: Date (yyyy-MM-dd)
- **Row Key**: Time + GUID for uniqueness
- **Properties**: LogLevel, Category, Message, Exception, etc.

## Development Helper Commands

The `dev-helper.ps1` script provides convenient commands for development:

```powershell
# Start Azurite storage emulator
.\dev-helper.ps1 start-azurite

# Stop Azurite storage emulator
.\dev-helper.ps1 stop-azurite

# Run the SMTP server
.\dev-helper.ps1 run-server

# Test the server functionality
.\dev-helper.ps1 test-server

# Check storage contents
.\dev-helper.ps1 check-storage

# Clean storage data
.\dev-helper.ps1 clean-storage

# Show help
.\dev-helper.ps1 help
```

## Implementation Details

### Components

1. **DefaultMessageStore**: Saves emails to Azure Blob Storage
2. **DefaultMailboxFilter**: Filters recipients (only allows TestUserOne@BlazorHelpWebsiteEmail.com)
3. **DefaultUserAuthenticator**: Authenticates SMTP relay users (Admin/password)
4. **TableStorageLogger**: Logs all operations to Azure Table Storage
5. **SmtpServerHostedService**: Manages the SMTP server lifecycle

### Security Features

- **Recipient Filtering**: Only specific email addresses can receive mail
- **Authentication**: SMTP relay requires username/password
- **Comprehensive Logging**: All operations are logged for audit purposes
- **Azure Storage Integration**: Uses Azure managed identity best practices

## Security Considerations

?? **Important Security Notes:**

1. **Default Credentials**: The default username/password (`Admin`/`password`) should be changed in production
2. **Network Security**: Consider firewall rules and network segmentation
3. **TLS/SSL**: The current implementation doesn't include TLS. Consider adding SSL/TLS for production
4. **Authentication**: The password is stored in plain text. Use secure password hashing in production
5. **Rate Limiting**: Consider implementing rate limiting to prevent abuse
6. **Port Security**: Development uses non-privileged ports (2525, 2587), production uses standard ports (25, 587)

## Monitoring

The application provides comprehensive logging:

1. **Console Logs**: Real-time monitoring during development
2. **Table Storage Logs**: Persistent logging for audit and troubleshooting
3. **Structured Logging**: All logs include contextual information like session IDs and transaction IDs

## Troubleshooting

### Common Issues

1. **Port Already in Use**:
   - Change ports in configuration
   - Use non-privileged ports (>1024) for development
   - Check if another SMTP server is running

2. **Storage Connection Issues**:
   - Verify Azurite is running: `.\dev-helper.ps1 start-azurite`
   - Check Azure Storage Account connection string
   - Ensure firewall allows connections

3. **Email Rejected**:
   - Verify recipient email matches `TestUserOne@BlazorHelpWebsiteEmail.com`
   - Check authentication credentials for relay
   - Review logs in console or Azure Table Storage

4. **Configuration File Not Found**:
   - Ensure you're running from the SMTPServerSvc directory
   - Check that appsettings.json exists

### Testing with Helper Script

```powershell
# Test server connectivity and functionality
.\dev-helper.ps1 test-server

# Check what's stored in Azurite
.\dev-helper.ps1 check-storage
```

### Logs Analysis

Query Table Storage logs to analyze SMTP operations:
- Filter by date using PartitionKey
- Search for specific sessions or errors
- Monitor authentication attempts

## Docker Support

Build and run with Docker:

```bash
# Build the Docker image
docker build -t blazor-smtp-server .

# Run with Docker (requires Azure Storage connection string)
docker run -p 25:25 -p 587:587 -e SmtpServer__StorageConnectionString="your-connection-string" blazor-smtp-server
```

## Development

To extend or modify the server:

1. **Custom Message Store**: Implement `IMessageStore` for different storage backends
2. **Custom Authentication**: Implement `IUserAuthenticator` for different auth mechanisms
3. **Custom Filters**: Implement `IMailboxFilter` for different recipient filtering logic
4. **Additional Logging**: Extend `TableStorageLogger` for custom log formats

### Project Structure

```
SMTPServerSvc/
??? Services/
?   ??? DefaultMessageStore.cs      # Blob storage for emails
?   ??? DefaultMailboxFilter.cs     # Recipient filtering
?   ??? DefaultUserAuthenticator.cs # SMTP authentication
?   ??? SmtpServerHostedService.cs # Server lifecycle
?   ??? TableStorageLogger.cs      # Azure Table logging
??? Configuration/
?   ??? SmtpServerConfiguration.cs # App configuration
??? appsettings.json               # Production config
??? appsettings.Development.json   # Development config
??? dev-helper.ps1                 # Development helper script
??? TestClient.cs                  # Test client
??? Program.cs                     # Application entry point
??? Dockerfile                     # Container configuration
??? README.md                      # This file
```

## License

This project is part of the BlazorSMTPServer solution and follows the same licensing terms.