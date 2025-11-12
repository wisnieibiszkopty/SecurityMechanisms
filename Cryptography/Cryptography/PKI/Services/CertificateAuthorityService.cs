using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Cryptography.Crypto.Models;
using Cryptography.PKI.Interfaces;
using Cryptography.PKI.Models;

namespace Cryptography.PKI.Services;

public class CertificateAuthorityService : ICertificateAuthorityService
{
    private readonly IPKIService _pkiService;
    
    private readonly KeyPair _keyPair;
    private readonly X509Certificate _rootCertificate;
    public X509Certificate RootCertificate => _rootCertificate;

    private HashSet<string> _certificateRevocationList = new(); 
    
    private string _beginText = "-----BEGIN CERTIFICATE-----";
    private string _endText = "-----END CERTIFICATE-----";
    
    public CertificateAuthorityService(IPKIService pkiService)
    {
        _pkiService = pkiService;
        _keyPair = _pkiService.GenerateSigningKeyPair();
        _rootCertificate = GenerateRootCertificate();
    }
    
    private X509Certificate GenerateRootCertificate()
    {
        var cert = new X509Certificate
        {
            SerialNumber = Guid.NewGuid().ToString(),
            Subject = "RootCA",
            Issuer = "RootCA",
            ValidFrom = DateTime.UtcNow,
            ValidTo = DateTime.UtcNow.AddYears(10),
            SignatureAlgorithm = "Ed25519",
            PublicKey = _keyPair.PublicKey
        };
        
        var dataToSign = cert.ComputeCertificateDigest();
        cert.Signature = _pkiService.SignData(dataToSign, _keyPair.PrivateKey);
        
        return cert;
    }

    public X509Certificate GenerateCertificate(string subject, byte[] publicKey)
    {
        var cert = new X509Certificate
        {
            SerialNumber = Guid.NewGuid().ToString(),
            Subject = subject,
            Issuer = RootCertificate.Subject,
            ValidFrom = DateTime.UtcNow,
            ValidTo = DateTime.UtcNow.AddDays(30),
            SignatureAlgorithm = "Ed25519",
            PublicKey = publicKey
        };
        
        var dataToSign = cert.ComputeCertificateDigest();
        cert.Signature = _pkiService.SignData(dataToSign, _keyPair.PrivateKey);
        
        return cert;
    }
    
    public bool VerifyCertificate(X509Certificate cert)
    {
        if (cert.ValidTo < DateTime.UtcNow)
        {
            return false;
        }

        if (_certificateRevocationList.Contains(cert.SerialNumber))
        {
            return false;
        }
        
        var dataToVerify = cert.ComputeCertificateDigest();
        return _pkiService.VerifySignature(dataToVerify, cert.Signature, _keyPair.PublicKey);
    }

    public void ExportCertificate(string filepath, X509Certificate cert)
    {
        var certificatePath = filepath + ".pem";
        var certJson = JsonSerializer.Serialize(cert);
        var certBytes = Encoding.UTF8.GetBytes(certJson);
        var base64 = Convert.ToBase64String(certBytes);
        var textToExport = $"{_beginText}{base64}{_endText}";
        
        int lineLength = 64;

        using (var writer = new StreamWriter(certificatePath))
        {
            for (int i = 0; i < textToExport.Length; i += lineLength)
            {
                int length = Math.Min(lineLength, textToExport.Length - i);
                writer.WriteLine(textToExport.Substring(i, length));
            }
        }

    }
    
    public X509Certificate ImportCertificate(string filepath)
    {
        string text = File.ReadAllText(filepath);
        int cutStart = _beginText.Length;
        int cutEnd = _endText.Length;
        
        var base64 = text.Substring(cutStart, text.Length - cutStart - cutEnd - 1);
        base64 = Regex.Replace(base64, @"\s+", "");

        var bytes = Convert.FromBase64String(base64);
        var json = Encoding.UTF8.GetString(bytes);

        var cert = JsonSerializer.Deserialize<X509Certificate>(json);
        if (cert == null)
        {
            throw new JsonException("Cannot deserialize this file to X509 certificate");
        }
        
        return cert;
    }

    public void AddCertificateToRevocationList(X509Certificate cert)
    {
        _certificateRevocationList.Add(cert.SerialNumber);
    }
    
    public void Dispose()
    {
        _keyPair?.Dispose();
    }
}