using System.Net;

namespace SMTPServerSvc.Services;

public class DnsResolver : IDnsResolver
{
    public Task<IPAddress[]> GetHostAddressesAsync(string hostNameOrAddress)
    {
        return Dns.GetHostAddressesAsync(hostNameOrAddress);
    }
}
