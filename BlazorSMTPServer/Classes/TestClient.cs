using System.Net.Mail;
using System.Net;

namespace SMTPServerSvc.TestClient;

/// <summary>
/// Simple test client to verify SMTP server functionality
/// </summary>
public class SmtpTestClient
{
    public static async Task TestSmtpServer()
    {
        try
        {
            Console.WriteLine("Testing SMTP Server...");
            
            // Test 1: Send email to allowed recipient without authentication (should work)
            await SendTestEmail("sender@example.com", "TestUserOne@BlazorHelpWebsiteEmail.com", 
                "Test Email Without Auth", "This is a test email without authentication.", false);

            // Test 2: Send email to disallowed recipient (should fail)
            await SendTestEmail("sender@example.com", "notallowed@example.com", 
                "Test Email to Disallowed Recipient", "This should fail.", false);

            // Test 3: Send email with authentication (should work)
            await SendTestEmail("sender@example.com", "TestUserOne@BlazorHelpWebsiteEmail.com", 
                "Test Email With Auth", "This is a test email with authentication.", true);

            Console.WriteLine("SMTP Server tests completed.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Test failed: {ex.Message}");
        }
    }

    private static async Task SendTestEmail(string from, string to, string subject, string body, bool useAuth)
    {
        try
        {
            using var client = new SmtpClient("localhost", 2525); // Use development port
            
            if (useAuth)
            {
                client.Credentials = new NetworkCredential("Admin", "password");
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
            Console.WriteLine($"? Successfully sent email to {to} (Auth: {useAuth})");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"? Failed to send email to {to} (Auth: {useAuth}): {ex.Message}");
        }
    }
}