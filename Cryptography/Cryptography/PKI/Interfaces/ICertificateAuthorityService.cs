using Cryptography.PKI.Models;

namespace Cryptography.PKI.Interfaces;

public interface ICertificateAuthorityService : IDisposable
{
    public X509Certificate RootCertificate { get; }
}