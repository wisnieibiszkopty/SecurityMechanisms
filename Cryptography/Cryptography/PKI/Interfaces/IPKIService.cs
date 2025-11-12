using Cryptography.Crypto.Models;
using LibSodium;

namespace Cryptography.PKI.Interfaces;

public interface IPKIService
{
    KeyPair GenerateSigningKeyPair();
    byte[] SignData(byte[] data, SecureMemory<byte> privateKey);
    bool VerifySignature(byte[] data, byte[] signature, byte[] publicKey);
}