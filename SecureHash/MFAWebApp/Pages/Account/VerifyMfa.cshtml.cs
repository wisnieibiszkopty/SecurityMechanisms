using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using MFAWebApp.Data;
using MFAWebApp.Services.TOTP;

namespace WebApp.Pages.Account
{
    public class VerifyMfaModel : PageModel
    {
        private readonly AppDbContext _db;
        private readonly ITotpService _totpService;

        public VerifyMfaModel(AppDbContext db, ITotpService totpService)
        {
            _db = db;
            _totpService = totpService;
        }

        [BindProperty]
        [Required(ErrorMessage = "A code from the Authenticator app is required.")]
        public string Code { get; set; }

        public async Task<IActionResult> OnPostAsync()
        {
            var pendingUserId = HttpContext.Session.GetInt32("PendingUserId");
            if (pendingUserId == null)
            {
                ModelState.AddModelError(string.Empty, "Your MFA session is expiring. Please log in again.");
                return RedirectToPage("/Account/Login");
            }
            var user = await _db.Users.FindAsync(pendingUserId);

            if (user == null) return RedirectToPage("/Account/Login");

            if (!string.IsNullOrWhiteSpace(Code) && !string.IsNullOrWhiteSpace(user.TotpSecret))
            {
                if (_totpService.VerifyCode(user.TotpSecret, Code))
                {
                    HttpContext.Session.Remove("PendingUserId");
                    HttpContext.Session.SetInt32("UserId", user.Id);
                    return RedirectToPage("/Index");
                }
            }
            //0h40E~Nfdfn#
            ModelState.AddModelError(string.Empty, "Invalid TOTP code");

            HttpContext.Session.Remove("PendingUserId");
            HttpContext.Session.SetInt32("PendingUserId", pendingUserId.Value);

            return Page();
        }
    }
}
