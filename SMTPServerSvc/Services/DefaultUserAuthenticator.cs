using Microsoft.Extensions.Logging;
using SmtpServer;
using SmtpServer.Authentication;
using SMTPServerSvc.Configuration;

namespace SMTPServerSvc.Services;

/// <summary>
/// User authenticator that only allows SMTP relay for configured username and password
/// </summary>
public class DefaultUserAuthenticator : IUserAuthenticator
{
    private readonly ILogger<DefaultUserAuthenticator> _logger;
    private readonly string _allowedUsername;
    private readonly string _allowedPassword;

    public DefaultUserAuthenticator(SmtpServerConfiguration configuration, ILogger<DefaultUserAuthenticator> logger)
    {
        _logger = logger;
        _allowedUsername = configuration.AllowedUsername;
        _allowedPassword = configuration.AllowedPassword;
        
        _logger.LogInformation("DefaultUserAuthenticator initialized. Only allowing user: {AllowedUsername}", _allowedUsername);
    }

    /// <summary>
    /// Asynchronously authenticates a user using the provided session context, username, and password.
    /// </summary>
    /// <param name="context">The session context associated with the authentication attempt. Must not be null.</param>
    /// <param name="user">The username to authenticate. Cannot be null or empty.</param>
    /// <param name="password">The password corresponding to the specified username. Cannot be null.</param>
    /// <param name="cancellationToken">A cancellation token that can be used to cancel the authentication operation.</param>
    /// <returns>A task that represents the asynchronous operation. The task result is <see langword="true"/> if authentication
    /// is successful; otherwise, <see langword="false"/>.</returns>
    #region public Task<bool> AuthenticateAsync(ISessionContext context, string user, string password, CancellationToken cancellationToken)
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
    #endregion
}