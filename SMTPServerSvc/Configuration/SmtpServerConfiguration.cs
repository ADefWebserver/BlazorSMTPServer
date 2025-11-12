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
    /// Blob container name for storing email messages
    /// </summary>
    public string BlobContainerName { get; set; } = string.Empty;

    /// <summary>
    /// Table name for storing logs
    /// </summary>
    public string LogTableName { get; set; } = string.Empty;
}