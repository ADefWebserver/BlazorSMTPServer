using System.Net;

namespace SMTPServerSvc.Services;

public interface IDnsResolver
{
    Task<IPAddress[]> GetHostAddressesAsync(string hostNameOrAddress);
}
