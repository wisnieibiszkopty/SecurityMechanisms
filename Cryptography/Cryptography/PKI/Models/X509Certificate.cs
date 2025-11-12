using System.Text;
using LibSodium;

namespace Cryptography.PKI.Models;

public class X509Certificate
{
    public string SerialNumber { get; set; }
    public string Subject { get; set; }
    public string Issuer { get; set; }
    public DateTime ValidFrom { get; set; }
    public DateTime ValidTo { get; set; }
    public string SignatureAlgorithm { get; set; }
    public byte[] PublicKey { get; set; }
    public byte[] Signature { get; set; }

    public byte[] ComputeCertificateDigest()
    {
        var rawData = Encoding.UTF8.GetBytes(
            $"{SerialNumber}|{Subject}|{Issuer}|{ValidFrom:O}|{ValidTo:O}|{Convert.ToBase64String(PublicKey)}"
        );

        Span<byte> hash = stackalloc byte[CryptoGenericHash.HashLen];
        CryptoGenericHash.ComputeHash(hash, rawData.AsSpan(), (SecureMemory<byte>)null);
        return hash.ToArray();
    }

    public override string ToString()
    {
        var sb = new StringBuilder();
        sb.AppendLine("----- Certificate Details -----");
        sb.AppendLine($"Serial Number: {SerialNumber}");
        sb.AppendLine($"Subject: {Subject}");
        sb.AppendLine($"Issuer: {Issuer}");
        sb.AppendLine($"Valid From: {ValidFrom:O}");
        sb.AppendLine($"Valid To: {ValidTo:O}");
        sb.AppendLine($"Signature Algorithm: {SignatureAlgorithm}");
        sb.AppendLine($"Public Key (Base64): {Convert.ToBase64String(PublicKey)}");
        sb.AppendLine($"Signature (Base64): {Convert.ToBase64String(Signature)}");
        sb.AppendLine("-------------------------------");
        return sb.ToString();
    }
}