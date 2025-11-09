using Microsoft.Extensions.Logging;
using SmtpServer;
using SmtpServer.Authentication;

namespace SMTPServerSvc.Services;

/// <summary>
/// User authenticator that only allows SMTP relay for user "Admin" with password "password"
/// </summary>
public class SampleUserAuthenticator : IUserAuthenticator
{
    private readonly ILogger<SampleUserAuthenticator> _logger;
    private readonly string _allowedUsername = "Admin";
    private readonly string _allowedPassword = "password";

    public SampleUserAuthenticator(ILogger<SampleUserAuthenticator> logger)
    {
        _logger = logger;
        _logger.LogInformation("SampleUserAuthenticator initialized. Only allowing user: {AllowedUsername}", _allowedUsername);
    }

    public Task<bool> AuthenticateAsync(ISessionContext context, string user, string password, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Authentication attempt for user: {Username} from {RemoteEndPoint}", 
            user, 
            context.Properties.ContainsKey("RemoteEndPoint") ? context.Properties["RemoteEndPoint"] : "unknown");

        // Check credentials (in production, use secure password hashing!)
        var isAuthenticated = string.Equals(user, _allowedUsername, StringComparison.Ordinal) &&
                             string.Equals(password, _allowedPassword, StringComparison.Ordinal);

        if (isAuthenticated)
        {
            _logger.LogInformation("Authentication successful for user: {Username}", user);
        }
        else
        {
            _logger.LogWarning("Authentication failed for user: {Username}. Invalid credentials", user);
        }

        return Task.FromResult(isAuthenticated);
    }
}