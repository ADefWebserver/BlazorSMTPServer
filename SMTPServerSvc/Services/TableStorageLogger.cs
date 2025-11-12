using Azure.Data.Tables;
using Azure;
using Microsoft.Extensions.Logging;

namespace SMTPServerSvc.Services;

/// <summary>
/// Logger that writes to Azure Table Storage for comprehensive SMTP operation tracking
/// </summary>
public class TableStorageLogger : ILogger
{
    private readonly TableClient? _tableClient;
    private readonly string _categoryName;
    private readonly bool _isAvailable;

    public TableStorageLogger(TableClient? tableClient, string categoryName, bool isAvailable = true)
    {
        _tableClient = tableClient;
        _categoryName = categoryName;
        _isAvailable = isAvailable;
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

        var message = formatter(state, exception);
        
        // Always log to console as fallback
        Console.WriteLine($"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff}] [{logLevel}] {_categoryName}: {message}");
        if (exception != null)
        {
            Console.WriteLine($"Exception: {exception}");
        }

        // Only attempt table storage if available
        if (!_isAvailable || _tableClient == null)
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
                ["Message"] = message,
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
            // Don't log table storage failures to avoid infinite loops
            // The console output above already provides the log entry
            Console.WriteLine($"Table storage logging failed: {ex.Message}");
        }
    }
}

/// <summary>
/// Logger provider for Azure Table Storage that works with Aspire-managed TableServiceClient
/// </summary>
public class TableStorageLoggerProvider : ILoggerProvider
{
    private readonly TableServiceClient _tableServiceClient;
    private readonly TableClient? _tableClient;
    private readonly string _tableName;
    private readonly bool _isAvailable;

    public TableStorageLoggerProvider(TableServiceClient tableServiceClient, string tableName = "SMTPServerLogs")
    {
        _tableServiceClient = tableServiceClient;
        _tableName = tableName;
        
        try
        {
            _tableClient = _tableServiceClient.GetTableClient(_tableName);
            
            // Test the connection and create table if it doesn't exist
            _tableClient.CreateIfNotExists();
            _isAvailable = true;
        }
        catch (Exception ex)
        {
            // Log the error but don't fail - gracefully degrade to console logging
            Console.WriteLine($"Warning: Table Storage logging unavailable: {ex.Message}");
            Console.WriteLine("Falling back to console logging only. Ensure Azurite is running for table storage logging.");
            _tableClient = null;
            _isAvailable = false;
        }
    }

    public ILogger CreateLogger(string categoryName)
    {
        return new TableStorageLogger(_tableClient, categoryName, _isAvailable);
    }

    public void Dispose()
    {
        // Nothing to dispose
    }
}