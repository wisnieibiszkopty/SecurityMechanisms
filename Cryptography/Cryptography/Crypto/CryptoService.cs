using System.Text;
using Cryptography.Crypto.Models;
using LibSodium;

namespace Cryptography.Crypto;

public class CryptoService : ICryptoService
{
    public SecureMemory<byte> GenerateSymmetricKey()
    { 
        var key = new SecureMemory<byte>(SecretBox.KeyLen);
        RandomGenerator.Fill(key);
        key.ProtectReadOnly();
        
        return key;
    }

    public byte[] EncryptSymmetricBytes(byte[] data, SecureMemory<byte> key)
    {
        Span<byte> ciphertext = stackalloc byte[data.Length + SecretBox.MacLen + SecretBox.NonceLen];
        SecretBox.Encrypt(ciphertext, data, key);
        return ciphertext.ToArray();
    }

    public byte[] DecryptSymmetricBytes(byte[] ciphertext, SecureMemory<byte> key)
    {
        int messageLength = ciphertext.Length - SecretBox.MacLen - SecretBox.NonceLen;
        if (messageLength < 0)
        {
            throw new ArgumentException("Ciphertext is too short or malformed.");
        }

        Span<byte> decrypted = stackalloc byte[messageLength];
        SecretBox.Decrypt(decrypted, ciphertext, key);
        
        return decrypted.ToArray();
    }

    public byte[] EncryptSymmetric(string plaintext, SecureMemory<byte> key)
    {
        byte[] messageBytes = EncodeUtf8(plaintext);
        return EncryptSymmetricBytes(messageBytes, key);
    }

    public string DecryptSymmetric(byte[] ciphertext, SecureMemory<byte> key)
    {
        byte[] decryptedBytes = DecryptSymmetricBytes(ciphertext, key);
        return DecodeUtf8(decryptedBytes);
    }

    public KeyPair GenerateAsymmetricKeyPair()
    {
        Span<byte> publicKey = stackalloc byte[CryptoBox.PublicKeyLen];
        var privateKey = new SecureMemory<byte>(CryptoBox.PrivateKeyLen);
        CryptoBox.GenerateKeypair(publicKey, privateKey);
        privateKey.ProtectReadOnly();
        return new KeyPair(publicKey.ToArray(), privateKey);
    }

    public byte[] EncryptAsymmetricBytes(byte[] data, byte[] recipientPublicKey, SecureMemory<byte> senderPrivateKey)
    {
        Span<byte> ciphertext = stackalloc byte[data.Length + CryptoBox.MacLen + CryptoBox.NonceLen];
        CryptoBox.EncryptWithKeypair(ciphertext, data, recipientPublicKey, senderPrivateKey);
        return ciphertext.ToArray();
    }

    public byte[] DecryptAsymmetricBytes(byte[] ciphertext, byte[] senderPublicKey, SecureMemory<byte> recipientPrivateKey)
    {
        int messageLength = ciphertext.Length - CryptoBox.MacLen - CryptoBox.NonceLen;
        if (messageLength < 0)
        {
            throw new ArgumentException("Ciphertext is too short or malformed.");   
        }
        Span<byte> decrypted = stackalloc byte[messageLength];
        CryptoBox.DecryptWithKeypair(decrypted, ciphertext, senderPublicKey, recipientPrivateKey);
        return decrypted.ToArray();
    }

    public byte[] EncryptAsymmetric(string plaintext, byte[] recipientPublicKey, SecureMemory<byte> senderPrivateKey)
    {
        byte[] messageBytes = EncodeUtf8(plaintext);
        return EncryptAsymmetricBytes(messageBytes, recipientPublicKey, senderPrivateKey);
    }

    public string DecryptAsymmetric(byte[] ciphertext, byte[] senderPublicKey, SecureMemory<byte> recipientPrivateKey)
    {
        byte[] decryptedBytes = DecryptAsymmetricBytes(ciphertext, senderPublicKey, recipientPrivateKey);
        return DecodeUtf8(decryptedBytes);
    }

    public string EncryptFileSecretStream(string filepath, byte[] recipientPublicKey, SecureMemory<byte> senderPrivateKey)
    {
        // klucz symetryczny do szyfrowania strumienia
        using var key = new SecureMemory<byte>(CryptoSecretStream.KeyLen);
        CryptoSecretStream.GenerateKey(key);
        key.ProtectReadOnly();
        
        // otwarcie pliku i utworzenie pliku z szyfrogramem
        var cipherPath = filepath + ".enc";
        using var inputFile = File.OpenRead(filepath);
        using var outputFile = File.Create(cipherPath);
        ReadOnlySpan<byte> keySpan = key.AsReadOnlySpan();
        Span<byte> ciphertext = stackalloc byte[key.Length + CryptoBox.MacLen + CryptoBox.NonceLen];
        
        // zaszyfrowanie samego klucza symetrycznego za pomocą kluczy asymetrycznych
        CryptoBox.EncryptWithKeypair(ciphertext, keySpan, recipientPublicKey, senderPrivateKey);
        outputFile.Write(BitConverter.GetBytes(ciphertext.Length));
        
        // zapis bajtów długości szyfrogramu
        outputFile.Write(ciphertext.ToArray()); // zapis zaszyfrowanego klucza
        
        // zaszyfrowanie całości danych symetrycznie w trybie strumieniowym
        SecretStream.Encrypt(inputFile, outputFile, key);
        
        return cipherPath;
    }

    public string DecryptFileSecretStream(string filepath, byte[] senderPublicKey, SecureMemory<byte> recipientPrivateKey)
    {
        // otwarcie zaszyfrowanego pliku
        using var inputFile = File.OpenRead(filepath);
        
        // odczytanie długości zaszyfrowanego klucza symetrycznego (liczby bajtów szyfrogramu) z pliku
        Span<byte> lengthBytes = stackalloc byte[4];
        inputFile.ReadExactly(lengthBytes);
        int encryptedKeyLen = BitConverter.ToInt32(lengthBytes);
        
        // odczytanie zaszyfrowanego klucza symetrycznego z pliku
        byte[] encryptedSymmetricKey = new byte[encryptedKeyLen];
        inputFile.ReadExactly(encryptedSymmetricKey, 0, encryptedKeyLen);
        
        // odszyfrowanie klucza symetrycznego za pomocąkryptografii asymetrycznej
        Span<byte> decryptedKey = stackalloc byte[CryptoSecretStream.KeyLen];
        CryptoBox.DecryptWithKeypair(decryptedKey, encryptedSymmetricKey, senderPublicKey, recipientPrivateKey);
        using var key = new SecureMemory<byte>(CryptoSecretStream.KeyLen);
        decryptedKey.CopyTo(key.AsSpan());
        key.ProtectReadOnly();
        
        // obróbka nazwy deszyfrowanego pliku
        string encryptedExtension = ".enc";
        string filenameWithoutEnc = filepath.EndsWith(encryptedExtension,
                StringComparison.OrdinalIgnoreCase)
                ? filepath[..^encryptedExtension.Length]
                : filepath;
        
        string extension = Path.GetExtension(filenameWithoutEnc);
        string baseName = Path.GetFileNameWithoutExtension(filenameWithoutEnc);
        string directory = Path.GetDirectoryName(filepath) ?? "";
        string decryptedFileName = !string.IsNullOrEmpty(extension)
                ? $"{baseName}_decrypted{extension}"
                : $"{baseName}_decrypted";
        string decryptedPath = Path.Combine(directory, decryptedFileName);

        using var decryptedFile = File.Create(decryptedPath);
        SecretStream.Decrypt(inputFile, decryptedFile, key);

        return decryptedPath;
    }

    private byte[] EncodeUtf8(string input) => Encoding.UTF8.GetBytes(input);
    private string DecodeUtf8(Span<byte> input) => Encoding.UTF8.GetString(input);
}