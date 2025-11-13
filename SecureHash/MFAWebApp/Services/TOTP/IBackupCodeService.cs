namespace MFAWebApp.Services.TOTP;

public interface IBackupCodeService
{
    Task<IReadOnlyList<string>> GenerateNewCodesAsync(int userId, int count = 10, int codeLength = 10);
    Task<bool> VerifyAndConsumeAsync(int userId, string code);
    Task<int> GetRemainingCountAsync(int userId);
    Task InvalidateAllAsync(int userId);
}