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

    public SampleMailboxFilterTests()
    {
        _mockLogger = new Mock<ILogger<SampleMailboxFilter>>();
        _mockDnsResolver = new Mock<IDnsResolver>();
        _config = new SmtpServerConfiguration { SpamhausKey = "testkey" };
    }

    private ISessionContext CreateSessionContext(bool isAuthenticated, string ipAddress = "1.2.3.4")
    {
        var context = new Mock<ISessionContext>();
        context.Setup(c => c.Properties).Returns(new Dictionary<string, object>());

        if (isAuthenticated)
        {
            context.Object.Properties["IsAuthenticated"] = true;
        }

        var remoteEndPoint = new IPEndPoint(IPAddress.Parse(ipAddress), 12345);
        context.Object.Properties["RemoteEndPoint"] = remoteEndPoint;

        return context.Object;
    }

    [Fact]
    public async Task CanAcceptFromAsync_AuthenticatedUser_ReturnsTrue()
    {
        // Arrange
        var filter = new SampleMailboxFilter(_config, _mockLogger.Object, _mockDnsResolver.Object);
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
        
        var filter = new SampleMailboxFilter(_config, _mockLogger.Object, _mockDnsResolver.Object);
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
    public async Task CanAcceptFromAsync_UnauthenticatedUser_IsListed_ReturnsFalse()
    {
        // Arrange
        _mockDnsResolver.Setup(d => d.GetHostAddressesAsync(It.IsAny<string>()))
                       .ReturnsAsync(new[] { IPAddress.Parse("127.0.0.2") });

        var filter = new SampleMailboxFilter(_config, _mockLogger.Object, _mockDnsResolver.Object);
        var context = CreateSessionContext(false, "4.5.6.7");
        var from = new Mailbox("test@test.com");
        var expectedQuery = "7.6.5.4.testkey.zen.dq.spamhaus.net";

        // Act
        var result = await filter.CanAcceptFromAsync(context, from, 1024, CancellationToken.None);

        // Assert
        Assert.False(result);
        _mockDnsResolver.Verify(d => d.GetHostAddressesAsync(expectedQuery), Times.Once);
    }
}
