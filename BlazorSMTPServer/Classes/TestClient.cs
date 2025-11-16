using System.Net.Mail;
using System.Net;
using Azure.Data.Tables;
using System.Text.Json;

namespace SMTPServerSvc.TestClient;

/// <summary>
/// Simple test client to verify SMTP server functionality
/// </summary>
public class SmtpTestClient
{
    public static async Task TestSmtpServer(TableServiceClient tableServiceClient, string smtpHost)
    {
        try
        {
            Console.WriteLine("Testing SMTP Server...");
            
            // Test 1: Send email to allowed recipient without authentication (should work)
            await SendTestEmail(tableServiceClient, smtpHost, "sender@example.com", "TestUserOne@BlazorHelpWebsiteEmail.com", 
                "Test Email Without Auth", "This is a test email without authentication.", false);

            // Test 2: Send email to disallowed recipient (should fail)
            await SendTestEmail(tableServiceClient, smtpHost, "sender@example.com", "notallowed@example.com", 
                "Test Email to Disallowed Recipient", "This should fail.", false);

            // Test 3: Send email with authentication (should work)
            await SendTestEmail(tableServiceClient, smtpHost, "sender@example.com", "TestUserOne@BlazorHelpWebsiteEmail.com", 
                "Test Email With Auth", "This is a test email with authentication.", true);

            Console.WriteLine("SMTP Server tests completed.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Test failed: {ex.Message}");
        }
    }

    private static async Task<int> GetFirstPortAsync(TableServiceClient tableServiceClient)
    {
        const string SettingsTableName = "SMTPSettings";
        const string PartitionKey = "SmtpServer";
        const string RowKey = "Current";
        try
        {
            var table = tableServiceClient.GetTableClient(SettingsTableName);
            var entityResponse = await table.GetEntityAsync<TableEntity>(PartitionKey, RowKey);
            var entity = entityResponse.Value;
            // Prefer PortsJson
            if (entity.TryGetValue("PortsJson", out var portsJsonObj) && portsJsonObj is string portsJson && !string.IsNullOrWhiteSpace(portsJson))
            {
                try
                {
                    var ports = JsonSerializer.Deserialize<int[]>(portsJson) ?? Array.Empty<int>();
                    var first = ports.FirstOrDefault();
                    if (first > 0) return first;
                }
                catch { /* ignore parse errors */ }
            }
            if (entity.TryGetValue("Ports", out var portsCsvObj) && portsCsvObj is string portsCsv && !string.IsNullOrWhiteSpace(portsCsv))
            {
                var firstStr = portsCsv.Split(',').Select(s => s.Trim()).FirstOrDefault();
                if (int.TryParse(firstStr, out var p) && p > 0) return p;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Warning: Could not read SMTP port from table storage, falling back to 2525. {ex.Message}");
        }
        return 2525; // fallback development port
    }

    private static async Task<(string? Username, string? Password)> GetCredentialsAsync(TableServiceClient tableServiceClient)
    {
        const string SettingsTableName = "SMTPSettings";
        const string PartitionKey = "SmtpServer";
        const string RowKey = "Current";
        try
        {
            var table = tableServiceClient.GetTableClient(SettingsTableName);
            var entityResponse = await table.GetEntityAsync<TableEntity>(PartitionKey, RowKey);
            var entity = entityResponse.Value;

            string? username = null;
            string? password = null;

            if (entity.TryGetValue("AllowedUsername", out var userObj))
            {
                username = userObj?.ToString();
            }
            if (entity.TryGetValue("AllowedPassword", out var passObj))
            {
                password = passObj?.ToString();
            }

            return (username, password);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Warning: Could not read SMTP credentials from table storage. {ex.Message}");
            return (null, null);
        }
    }

    private static async Task SendTestEmail(TableServiceClient tableServiceClient, string smtpHost, string from, string to, string subject, string body, bool useAuth)
    {
        try
        {
            var port = await GetFirstPortAsync(tableServiceClient);
            using var client = new SmtpClient(smtpHost, port); // Use same host/IP as Blazor site
            
            if (useAuth)
            {
                var (username, password) = await GetCredentialsAsync(tableServiceClient);
                if (!string.IsNullOrWhiteSpace(username) && !string.IsNullOrWhiteSpace(password))
                {
                    client.Credentials = new NetworkCredential(username, password);
                }
                else
                {
                    Console.WriteLine("Warning: Missing SMTP credentials in settings; proceeding without authentication.");
                }
            }
            
            client.EnableSsl = false;
            client.Timeout = 5000;

            var message = new MailMessage
            {
                From = new MailAddress(from),
                Subject = subject,
                Body = body
            };
            message.To.Add(to);

            await client.SendMailAsync(message);
            Console.WriteLine($"? Successfully sent email to {to} (Auth: {useAuth}, Host: {smtpHost}, Port: {port})");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"? Failed to send email to {to} (Auth: {useAuth}): {ex.Message}");
        }
    }
}