using OtpNet;

namespace MFAWebApp.Services.TOTP;

public class TotpService : ITotpService
{
    public string GenerateSecret()
    {
        var bytes = KeyGeneration.GenerateRandomKey(20);
        return Base32Encoding.ToString(bytes);
    }

    public string GenerateQrUri(string secret, string email, string appName)
    {
        return $"otpauth://totp/{appName}:{email}?secret={secret}&issuer={appName}&digits=6";
    }

    public bool VerifyCode(string secret, string code)
    {
        var bytes = Base32Encoding.ToBytes(secret);
        var totp = new Totp(bytes, step: 30, totpSize: 6);
        return totp.VerifyTotp(code, out _);
    }
}