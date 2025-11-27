namespace SMTPServerSvc.Configuration;

/// <summary>
/// Configuration settings for the SMTP server
/// </summary>
public class SmtpServerConfiguration
{
    public const string SectionName = "SmtpServer";

    /// <summary>
    /// Azure Storage connection string for Azurite or Azure Storage Account
    /// </summary>
    public string StorageConnectionString { get; set; } = string.Empty;

    /// <summary>
    /// SMTP server name identifier
    /// </summary>
    public string ServerName { get; set; } = string.Empty;

    /// <summary>
    /// SMTP server ports
    /// </summary>
    public int[] Ports { get; set; } = [];

    /// <summary>
    /// Allowed recipient email address
    /// </summary>
    public string AllowedRecipient { get; set; } = string.Empty;

    /// <summary>
    /// Allowed relay username
    /// </summary>
    public string AllowedUsername { get; set; } = string.Empty;

    /// <summary>
    /// Allowed relay password (in production, use secure configuration!)
    /// </summary>
    public string AllowedPassword { get; set; } = string.Empty;

    /// <summary>
    /// Optional Spamhaus API key used for spam checks
    /// </summary>
    public string SpamhausKey { get; set; } = string.Empty;

    /// <summary>
    /// If true, use the public Spamhaus mirror (zen.spamhaus.org) when no key is provided.
    /// CAUTION: Public mirror has usage limits and policy restrictions.
    /// </summary>
    public bool UsePublicSpamhausMirror { get; set; } = false;

    /// <summary>
    /// Enable SPF check
    /// </summary>
    public bool EnableSpfCheck { get; set; } = false;

    /// <summary>
    /// Enable DMARC check
    /// </summary>
    public bool EnableDmarcCheck { get; set; } = false;

    /// <summary>
    /// Enable DKIM check
    /// </summary>
    public bool EnableDkimCheck { get; set; } = false;

    /// <summary>
    /// If true, enables spam filtering.
    /// </summary>
    public bool EnableSpamFiltering { get; set; } = false;

}