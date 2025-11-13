using MFAWebApp.Data;
using MFAWebApp.Models;
using MFAWebApp.Services.Authentication;
using Microsoft.EntityFrameworkCore;
using OtpNet;

namespace MFAWebApp.Services.TOTP;

public class BackupCodeService : IBackupCodeService
{
    private readonly IPasswordHasher _hasher;
    private readonly AppDbContext _db;
    
    public BackupCodeService(AppDbContext db, IPasswordHasher hasher)
    {
        _db = db;
        _hasher = hasher;
    }

    private async Task<List<BackupCode>> GetCodesForUsers(int userId)
    {
        return await _db.BackupCodes
            .Where(c => c.UserId == userId && !c.Used)
            .ToListAsync();
    }
    
    public async Task<IReadOnlyList<string>> GenerateNewCodesAsync(int userId, int count = 10, int codeLength = 10)
    {
        var backupCodes = new List<string>();
        for (int i = 0; i < count; i++)
        {
            var bytes = KeyGeneration.GenerateRandomKey(codeLength);
            var code = Base32Encoding.ToString(bytes);   
            backupCodes.Add(code);

            var hashedCode = _hasher.Hash(code);
            var backupCode = new BackupCode
            {
                UserId = userId,
                CodeHash = hashedCode
            };
            _db.BackupCodes.Add(backupCode);
        }

        await _db.SaveChangesAsync();
        
        return backupCodes.AsReadOnly();
    }

    public async Task<bool> VerifyAndConsumeAsync(int userId, string code)
    {
        var userCodes = await GetCodesForUsers(userId);

        var isVerified = false;
        
        foreach (var userCode in userCodes)
        {
            isVerified = _hasher.Verify(code, userCode.CodeHash);
            if (isVerified)
            {
                userCode.Used = true;
                await _db.SaveChangesAsync();
                break;
            }
        }

        return isVerified;
    }

    public async Task<int> GetRemainingCountAsync(int userId)
    {
        return await _db.BackupCodes
            .Where(c => c.UserId == userId && !c.Used)
            .CountAsync();
    }

    public async Task InvalidateAllAsync(int userId)
    {
        var codes = await GetCodesForUsers(userId);
        foreach (var code in codes)
        {
            code.Used = true;
        }

        await _db.SaveChangesAsync();
    }
}