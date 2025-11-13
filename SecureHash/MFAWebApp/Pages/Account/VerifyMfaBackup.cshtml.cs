using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using MFAWebApp.Data;
using MFAWebApp.Services.TOTP;

namespace WebApp.Pages.Account
{
    public class VerifyMfaBackupModel : PageModel
    {
        private readonly AppDbContext _db;
        private readonly IBackupCodeService _backupCodeService;

        public VerifyMfaBackupModel(AppDbContext db, IBackupCodeService backupCodeService)
        {
            _db = db;
            _backupCodeService = backupCodeService;
        }

        [BindProperty]
        [Required(ErrorMessage = "A one-time backup code is required")]
        public string BackupCode { get; set; }

        public async Task<IActionResult> OnPostAsync()
        {
            var pendingUserId = HttpContext.Session.GetInt32("PendingUserId");
            if (pendingUserId == null)
            {
                ModelState.AddModelError(string.Empty, "Your MFA session is expiring. Please log in again");
                return RedirectToPage("/Account/Login");
            }
            var user = await _db.Users.FindAsync(pendingUserId);

            if (user == null) return RedirectToPage("/Account/Login");

            if (!string.IsNullOrWhiteSpace(BackupCode))
            {
                var success = await _backupCodeService.VerifyAndConsumeAsync(user.Id, BackupCode.Trim());

                if (success)
                {
                    user.MfaEnabled = false;
                    user.TotpSecret = null;
                    await _db.SaveChangesAsync();

                    HttpContext.Session.Remove("PendingUserId");
                    HttpContext.Session.SetInt32("UserId", user.Id);
                    return RedirectToPage("/Account/EnableMfa");
                }
            }

            ModelState.AddModelError(string.Empty, "Invalid backup code");

            HttpContext.Session.Remove("PendingUserId");
            HttpContext.Session.SetInt32("PendingUserId", pendingUserId.Value);

            return Page();
        }
    }
}
