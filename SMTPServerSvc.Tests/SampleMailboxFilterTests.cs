using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Moq;
using SmtpServer;
using SmtpServer.Mail;
using SMTPServerSvc.Configuration;
using SMTPServerSvc.Services;
using System.Net;
using System.Net.Sockets;

namespace SMTPServerSvc.Tests;

public class SampleMailboxFilterTests
{
    private readonly Mock<ILogger<SampleMailboxFilter>> _mockLogger;
    private readonly Mock<IDnsResolver> _mockDnsResolver;
    private readonly SmtpServerConfiguration _config;
    private readonly IMemoryCache _memoryCache;

    public SampleMailboxFilterTests()
    {
        _mockLogger = new Mock<ILogger<SampleMailboxFilter>>();
        _mockDnsResolver = new Mock<IDnsResolver>();
        _config = new SmtpServerConfiguration { SpamhausKey = "", ServerName = "test.com", AllowedRecipient = "allowed" };
        _memoryCache = new MemoryCache(new MemoryCacheOptions());
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
        var filter = new SampleMailboxFilter(_config, _mockLogger.Object, _mockDnsResolver.Object, _memoryCache);
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
        
        var filter = new SampleMailboxFilter(_config, _mockLogger.Object, _mockDnsResolver.Object, _memoryCache);
        var context = CreateSessionContext(false, "1.2.3.4");
        var from = new Mailbox("test@test.com");
        var expectedQuery = "4.3.2.1.testkey.zen.dq.spamhaus.net";

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

        var filter = new SampleMailboxFilter(_config, _mockLogger.Object, _mockDnsResolver.Object, _memoryCache);
        var context = CreateSessionContext(false, "4.5.6.7");
        var from = new Mailbox("test@test.com");
        var expectedQuery = "7.6.5.4.testkey.zen.dq.spamhaus.net";

        // Act
        var result = await filter.CanAcceptFromAsync(context, from, 1024, CancellationToken.None);

        // Assert
        Assert.True(result); // Should still return true
        Assert.True(context.Properties.ContainsKey("IsSpam"));
        Assert.True((bool)context.Properties["IsSpam"]);
        _mockDnsResolver.Verify(d => d.GetHostAddressesAsync(expectedQuery), Times.Once);
    }
}
