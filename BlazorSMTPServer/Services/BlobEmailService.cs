using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Text;

namespace BlazorSMTPServer.Services;

public record EmailListItem(
    string Id,
    string Subject,
    string From,
    DateTimeOffset Received,
    string RecipientUser,
    long Size,
    string BlobName,
    string Container
);

public record EmailMessage(
    EmailListItem Metadata,
    string RawEml
);

/// <summary>
/// Reads messages saved by SMTP service from Azure Blob Storage. Messages are saved as EML files with
/// extra X-SMTP-Server-* headers that we parse for metadata.
/// </summary>
public class BlobEmailService
{
    private readonly BlobServiceClient _blobServiceClient;
    private readonly ILogger<BlobEmailService> _logger;
    private readonly string _containerName;

    public BlobEmailService(BlobServiceClient blobServiceClient, IConfiguration configuration, ILogger<BlobEmailService> logger)
    {
        _blobServiceClient = blobServiceClient;
        _logger = logger;
        // Prefer app config, then env var from SMTP service, then default
        _containerName = configuration["EmailClient:BlobContainerName"]
                          ?? Environment.GetEnvironmentVariable("SmtpServer__BlobContainerName")
                          ?? "email-messages";
    }

    public async Task<IReadOnlyList<string>> GetRecipientFoldersAsync(CancellationToken ct = default)
    {
        var container = _blobServiceClient.GetBlobContainerClient(_containerName);
        var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        await foreach (var blob in container.GetBlobsAsync(prefix: null, cancellationToken: ct))
        {
            var name = blob.Name;
            var slash = name.IndexOf('/');
            if (slash > 0)
            {
                var folder = name.Substring(0, slash);
                if (!string.Equals(folder, ".$logs", StringComparison.Ordinal))
                    results.Add(folder);
            }
        }
        return results.OrderBy(s => s).ToList();
    }

    public async Task<IReadOnlyList<EmailListItem>> ListEmailsAsync(string recipientFolder, CancellationToken ct = default)
    {
        var container = _blobServiceClient.GetBlobContainerClient(_containerName);
        var prefix = string.IsNullOrWhiteSpace(recipientFolder) ? null : recipientFolder.Trim('/') + "/";
        var items = new List<EmailListItem>();

        await foreach (var blob in container.GetBlobsAsync(prefix: prefix, traits: BlobTraits.Metadata, states: BlobStates.None, cancellationToken: ct))
        {
            if (!blob.Name.EndsWith(".eml", StringComparison.OrdinalIgnoreCase))
                continue;

            var metaRecipient = blob.Metadata.TryGetValue("RecipientUser", out var recipient) ? recipient : recipientFolder;
            var received = blob.Properties.CreatedOn ?? blob.Properties.LastModified ?? DateTimeOffset.UtcNow;
            var size = blob.Properties.ContentLength ?? 0;

            items.Add(new EmailListItem(
                Id: blob.Name,
                Subject: blob.Metadata.TryGetValue("Subject", out var subj) ? subj : "(no subject)",
                From: blob.Metadata.TryGetValue("From", out var from) ? from : "",
                Received: received,
                RecipientUser: metaRecipient ?? "",
                Size: size,
                BlobName: blob.Name,
                Container: _containerName
            ));
        }

        // Sort newest first
        return items.OrderByDescending(i => i.Received).ToList();
    }

    public async Task<EmailMessage?> GetEmailAsync(string blobName, CancellationToken ct = default)
    {
        var container = _blobServiceClient.GetBlobContainerClient(_containerName);
        var blob = container.GetBlobClient(blobName);
        if (!await blob.ExistsAsync(ct))
        {
            _logger.LogWarning("Blob not found: {Blob}", blobName);
            return null;
        }

        using var ms = new MemoryStream();
        await blob.DownloadToAsync(ms, ct);
        ms.Position = 0;
        var raw = Encoding.UTF8.GetString(ms.ToArray());

        // Quick header parse for Subject/From if not in metadata
        string subject = TryGetHeader(raw, "Subject") ?? "(no subject)";
        string from = TryGetHeader(raw, "From") ?? "";
        string recipient = TryGetHeader(raw, "X-SMTP-Server-Recipient-User") ?? "";
        string receivedAt = TryGetHeader(raw, "X-SMTP-Server-Received") ?? DateTime.UtcNow.ToString("R");
        var received = DateTimeOffset.TryParse(receivedAt, out var r) ? r : DateTimeOffset.UtcNow;

        var props = await blob.GetPropertiesAsync(cancellationToken: ct);
        var size = props.Value.ContentLength;

        var item = new EmailListItem(
            Id: blobName,
            Subject: subject,
            From: from,
            Received: received,
            RecipientUser: recipient,
            Size: size,
            BlobName: blobName,
            Container: _containerName
        );

        return new EmailMessage(item, raw);
    }

    private static string? TryGetHeader(string eml, string header)
    {
        using var reader = new StringReader(eml);
        string? line;
        var headerPrefix = header + ":";
        while ((line = reader.ReadLine()) != null)
        {
            if (line.StartsWith(headerPrefix, StringComparison.OrdinalIgnoreCase))
            {
                return line.Substring(headerPrefix.Length).Trim();
            }
            if (string.IsNullOrWhiteSpace(line))
                break; // end of headers
        }
        return null;
    }
}
