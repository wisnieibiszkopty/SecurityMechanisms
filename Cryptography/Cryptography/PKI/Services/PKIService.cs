using Cryptography.Crypto.Models;
using Cryptography.PKI.Interfaces;
using LibSodium;

namespace Cryptography.PKI.Services;

public class PKIService : IPKIService
{
    public KeyPair GenerateSigningKeyPair()
    {
        Span<byte> publicKey = stackalloc byte[CryptoSign.PublicKeyLen];
        var privateKey = new SecureMemory<byte>(CryptoSign.PrivateKeyLen);
        CryptoSign.GenerateKeyPair(publicKey, privateKey);
        privateKey.ProtectReadOnly();

        return new KeyPair(publicKey.ToArray(), privateKey);
    }

    public byte[] SignData(byte[] data, SecureMemory<byte> privateKey)
    {
        byte[] signature = new byte[CryptoSign.SignatureLen];
        CryptoSign.Sign(data, signature, privateKey);

        return signature;
    }

    public bool VerifySignature(byte[] data, byte[] signature, byte[] publicKey)
    {
        return CryptoSign.Verify(data, signature, publicKey);
    }
}