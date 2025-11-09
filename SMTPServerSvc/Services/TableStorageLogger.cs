using Azure.Data.Tables;
using Azure;
using Microsoft.Extensions.Logging;

namespace SMTPServerSvc.Services;

/// <summary>
/// Logger that writes to Azure Table Storage for comprehensive SMTP operation tracking
/// </summary>
public class TableStorageLogger : ILogger
{
    private readonly TableClient _tableClient;
    private readonly string _categoryName;

    public TableStorageLogger(TableClient tableClient, string categoryName)
    {
        _tableClient = tableClient;
        _categoryName = categoryName;
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information && !ShouldFilterCategory(_categoryName);

    private static bool ShouldFilterCategory(string categoryName)
    {
        // Exclude Azure SDK logs to prevent circular logging
        return categoryName.StartsWith("Azure.") ||
               categoryName.StartsWith("System.Net.Http") ||
               categoryName.StartsWith("Microsoft.Extensions.Http");
    }

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel))
            return;

        try
        {
            var entity = new TableEntity
            {
                PartitionKey = DateTime.UtcNow.ToString("yyyy-MM-dd"),
                RowKey = $"{DateTime.UtcNow:HHmmss.fff}_{Guid.NewGuid():N}",
                ["Timestamp"] = DateTime.UtcNow,
                ["LogLevel"] = logLevel.ToString(),
                ["Category"] = _categoryName,
                ["EventId"] = eventId.Id,
                ["EventName"] = eventId.Name ?? "",
                ["Message"] = formatter(state, exception),
                ["Exception"] = exception?.ToString() ?? ""
            };

            // Add state properties if available
            if (state is IEnumerable<KeyValuePair<string, object>> properties)
            {
                foreach (var prop in properties.Where(p => p.Key != "{OriginalFormat}"))
                {
                    var key = prop.Key.Replace(".", "_"); // Table storage doesn't like dots in property names
                    entity[key] = prop.Value?.ToString() ?? "";
                }
            }

            // Use fire-and-forget to avoid blocking and potential deadlocks
            _ = _tableClient.AddEntityAsync(entity);
        }
        catch (Exception ex)
        {
            // Fallback to console if table storage fails
            Console.WriteLine($"Failed to log to table storage: {ex.Message}");
            Console.WriteLine($"[{logLevel}] {_categoryName}: {formatter(state, exception)}");
        }
    }
}

/// <summary>
/// Logger provider for Azure Table Storage that works with Aspire-managed TableServiceClient
/// </summary>
public class TableStorageLoggerProvider : ILoggerProvider
{
    private readonly TableServiceClient _tableServiceClient;
    private readonly TableClient _tableClient;

    public TableStorageLoggerProvider(TableServiceClient tableServiceClient)
    {
        _tableServiceClient = tableServiceClient;
        _tableClient = _tableServiceClient.GetTableClient("SMTPServerLogs");
        
        // Create table if it doesn't exist
        _tableClient.CreateIfNotExists();
    }

    public ILogger CreateLogger(string categoryName)
    {
        return new TableStorageLogger(_tableClient, categoryName);
    }

    public void Dispose()
    {
        // Nothing to dispose
    }
}