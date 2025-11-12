using Cryptography.Crypto.Models;
using Cryptography.PKI.Models;

namespace SecureChat.Context;

public class UserContext
{
    public string Username { get; set; }
    public KeyPair EncryptionKeys { get; set; }
    public KeyPair SigningKeys { get; set; }
    public X509Certificate Certificate { get; set; }
}