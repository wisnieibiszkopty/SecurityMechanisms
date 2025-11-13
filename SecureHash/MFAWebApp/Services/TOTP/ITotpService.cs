namespace MFAWebApp.Services.TOTP;

public interface ITotpService
{
    string GenerateSecret();
    string GenerateQrUri(string secret, string email, string appName);
    bool VerifyCode(string secret, string code);
}