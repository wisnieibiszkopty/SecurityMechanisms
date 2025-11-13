using LibSodium;

namespace Cryptography.Crypto.Models;

public class KeyPair(byte[] publicKey, SecureMemory<byte> privateKey) : IDisposable
{
    public byte[] PublicKey { get; } = publicKey
        ?? throw new ArgumentNullException(nameof(publicKey));

    public SecureMemory<byte> PrivateKey { get; } = privateKey 
        ?? throw new ArgumentNullException(nameof(privateKey));

    public void Dispose()
    {
        PrivateKey.Dispose();
    }
}