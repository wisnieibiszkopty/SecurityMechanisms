using System.Security.Cryptography;
using System.Text;
using MFAWebApp.Services.Authentication;
using Microsoft.Extensions.Configuration;

namespace HashDemo;

public class Sha256Hasher : IPasswordHasher
{
    private string _pepper;
    private string _salt;
    
    public Sha256Hasher(IConfiguration config)
    {
        _pepper = config["Security:PasswordPepper"] ??
                  throw new InvalidOperationException("Missing PasswordPepper in configuration");
        _salt = config["Security:PasswordSalt"] ??
                  throw new InvalidOperationException("Missing PasswordSalt in configuration");
    }
    
    public string Hash(string password)
    {
        using var sha = SHA256.Create();
        var combined = password + _salt + _pepper;
        var bytes = Encoding.UTF8.GetBytes(combined);
        var hash = sha.ComputeHash(bytes);
        return Convert.ToHexString(hash);
    }
    
    public bool Verify(string password, string storedHash)
    {
        var hashToVerify = Hash(password);
        return storedHash.Equals(hashToVerify, StringComparison.OrdinalIgnoreCase);
    }
}