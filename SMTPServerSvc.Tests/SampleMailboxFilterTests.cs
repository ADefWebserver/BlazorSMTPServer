using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Azure.Data.Tables;
using Azure.Data.Tables.Models;
using Azure;
using Moq;
using SmtpServer;
using SmtpServer.Mail;
using SMTPServerSvc.Configuration;
using SMTPServerSvc.Services;
using System.Net;
using System.Net.Sockets;

namespace SMTPServerSvc.Tests;

public class DefaultMailboxFilterTests
{
    private readonly Mock<ILogger<DefaultMailboxFilter>> _mockLogger;
    private readonly Mock<IDnsResolver> _mockDnsResolver;
    private readonly SmtpServerConfiguration _config;
    private readonly IMemoryCache _memoryCache;
    private readonly Mock<TableServiceClient> _mockTableServiceClient;
    private readonly Mock<TableClient> _mockTableClient;

    public DefaultMailboxFilterTests()
    {
        _mockLogger = new Mock<ILogger<DefaultMailboxFilter>>();
        _mockDnsResolver = new Mock<IDnsResolver>();
        _config = new SmtpServerConfiguration { SpamhausKey = "", ServerName = "test.com", AllowedRecipient = "allowed" };
        _memoryCache = new MemoryCache(new MemoryCacheOptions());

        _mockTableServiceClient = new Mock<TableServiceClient>();
        _mockTableClient = new Mock<TableClient>();

        _mockTableServiceClient.Setup(x => x.GetTableClient(It.IsAny<string>()))
            .Returns(_mockTableClient.Object);

        _mockTableClient.Setup(x => x.CreateIfNotExists(It.IsAny<CancellationToken>()))
            .Returns((Response<TableItem>)null!);

        _mockTableClient.Setup(x => x.AddEntityAsync(It.IsAny<TableEntity>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Response)null!);
    }

    private ISessionContext CreateSessionContext(bool isAuthenticated, string ipAddress = "1.2.3.4")
    {
        var context = new Mock<ISessionContext>();
        var properties = new Dictionary<string, object>();
        context.Setup(c => c.Properties).Returns(properties);

        if (isAuthenticated)
        {
            properties["IsAuthenticated"] = true;
        }

        var remoteEndPoint = new IPEndPoint(IPAddress.Parse(ipAddress), 12345);
        properties["RemoteEndPoint"] = remoteEndPoint;

        return context.Object;
    }

    [Fact]
    public async Task CanAcceptFromAsync_AuthenticatedUser_ReturnsTrue()
    {
        // Arrange
        var filter = new DefaultMailboxFilter(_config, _mockLogger.Object, _mockDnsResolver.Object, _memoryCache, _mockTableServiceClient.Object);
        var context = CreateSessionContext(true);
        var from = new Mailbox("test@test.com");

        // Act
        var result = await filter.CanAcceptFromAsync(context, from, 1024, CancellationToken.None);

        // Assert
        Assert.True(result);
        _mockDnsResolver.Verify(d => d.GetHostAddressesAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task CanAcceptFromAsync_UnauthenticatedUser_NotListed_ReturnsTrue()
    {
        // Arrange
        _mockDnsResolver.Setup(d => d.GetHostAddressesAsync(It.IsAny<string>()))
                       .ThrowsAsync(new SocketException((int)SocketError.HostNotFound));

        var filter = new DefaultMailboxFilter(_config, _mockLogger.Object, _mockDnsResolver.Object, _memoryCache, _mockTableServiceClient.Object);
        var context = CreateSessionContext(false, "1.2.3.4");
        var from = new Mailbox("test@test.com");
        // Since EnableSpamFiltering is false, should use public mirror
        var expectedQuery = "4.3.2.1.zen.spamhaus.org";

        // Act
        var result = await filter.CanAcceptFromAsync(context, from, 1024, CancellationToken.None);

        // Assert
        Assert.True(result);
        _mockDnsResolver.Verify(d => d.GetHostAddressesAsync(expectedQuery), Times.Once);
    }

    [Fact]
    public async Task CanAcceptFromAsync_UnauthenticatedUser_IsListed_TagsSessionAndReturnsTrue()
    {
        // Arrange
        _mockDnsResolver.Setup(d => d.GetHostAddressesAsync(It.IsAny<string>()))
                       .ReturnsAsync(new[] { IPAddress.Parse("127.0.0.2") });

        var filter = new DefaultMailboxFilter(_config, _mockLogger.Object, _mockDnsResolver.Object, _memoryCache, _mockTableServiceClient.Object);
        var context = CreateSessionContext(false, "4.5.6.7");
        var from = new Mailbox("test@test.com");
        // Since EnableSpamFiltering is false, should use public mirror
        var expectedQuery = "7.6.5.4.zen.spamhaus.org";

        // Act
        var result = await filter.CanAcceptFromAsync(context, from, 1024, CancellationToken.None);

        // Assert
        Assert.True(result); // Should still return true
        Assert.True(context.Properties.ContainsKey("IsSpam"));
        Assert.True((bool)context.Properties["IsSpam"]);
        Assert.True(context.Properties.ContainsKey("SpamIP"));
        Assert.Equal("4.5.6.7", context.Properties["SpamIP"]);
        _mockDnsResolver.Verify(d => d.GetHostAddressesAsync(expectedQuery), Times.Once);

        // Verify that spam was logged to table storage
        _mockTableClient.Verify(t => t.AddEntityAsync(It.Is<TableEntity>(e =>
            e.PartitionKey == DateTime.UtcNow.ToString("yyyy-MM-dd") &&
            e["Status"].ToString() == "Detected" &&
            e["IP"].ToString() == "4.5.6.7"
        ), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task CanAcceptFromAsync_WithSpamFilteringEnabled_UsesPrivateKey()
    {
        // Arrange
        var configWithKey = new SmtpServerConfiguration
        {
            SpamhausKey = "mykey",
            EnableSpamFiltering = true,
            ServerName = "test.com",
            AllowedRecipient = "allowed"
        };

        _mockDnsResolver.Setup(d => d.GetHostAddressesAsync(It.IsAny<string>()))
                       .ThrowsAsync(new SocketException((int)SocketError.HostNotFound));

        var filter = new DefaultMailboxFilter(configWithKey, _mockLogger.Object, _mockDnsResolver.Object, _memoryCache, _mockTableServiceClient.Object);
        var context = CreateSessionContext(false, "8.8.8.8");
        var from = new Mailbox("test@test.com");
        // Since EnableSpamFiltering is true AND key is provided, should use private mirror
        // IP address octets are reversed
        var expectedQuery = "8.8.8.8.mykey.zen.dq.spamhaus.net";

        // Act
        var result = await filter.CanAcceptFromAsync(context, from, 1024, CancellationToken.None);

        // Assert
        Assert.True(result);
        _mockDnsResolver.Verify(d => d.GetHostAddressesAsync(expectedQuery), Times.Once);
    }

    [Fact]
    public async Task CanAcceptFromAsync_WithKeyButFilteringDisabled_UsesPublicMirror()
    {
        // Arrange
        var configWithKeyButDisabled = new SmtpServerConfiguration
        {
            SpamhausKey = "mykey",
            EnableSpamFiltering = false, // Disabled
            ServerName = "test.com",
            AllowedRecipient = "allowed"
        };

        _mockDnsResolver.Setup(d => d.GetHostAddressesAsync(It.IsAny<string>()))
                       .ThrowsAsync(new SocketException((int)SocketError.HostNotFound));

        var filter = new DefaultMailboxFilter(configWithKeyButDisabled, _mockLogger.Object, _mockDnsResolver.Object, _memoryCache, _mockTableServiceClient.Object);
        var context = CreateSessionContext(false, "9.9.9.9");
        var from = new Mailbox("test@test.com");
        // Since EnableSpamFiltering is false, should use public mirror even with key present
        // IP address octets are reversed
        var expectedQuery = "9.9.9.9.zen.spamhaus.org";

        // Act
        var result = await filter.CanAcceptFromAsync(context, from, 1024, CancellationToken.None);

        // Assert
        Assert.True(result);
        _mockDnsResolver.Verify(d => d.GetHostAddressesAsync(expectedQuery), Times.Once);
    }
}
