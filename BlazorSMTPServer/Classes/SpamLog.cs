using Azure;
using Azure.Data.Tables;

namespace BlazorSMTPServer.Classes;

public class SpamLog : ITableEntity
{
    public string PartitionKey { get; set; } = default!;
    public string RowKey { get; set; } = default!;
    public DateTimeOffset? Timestamp { get; set; }
    public ETag ETag { get; set; }

    public string? SessionId { get; set; }
    public string? TransactionId { get; set; }
    public string? From { get; set; }
    public string? To { get; set; }
    public string? Subject { get; set; }
    public string? BlobPath { get; set; }
    public string? IP { get; set; }
}
