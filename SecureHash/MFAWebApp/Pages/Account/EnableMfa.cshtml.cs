using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using MFAWebApp.Data;
using MFAWebApp.Services.TOTP;

namespace MFAWebApp.Pages.Account;

public class EnableMfaModel : PageModel
{
    private readonly string APP_NAME = "MFAWebApp";
    
    private readonly AppDbContext _db;
    private readonly ITotpService _totpService;

    public EnableMfaModel(AppDbContext db, ITotpService totpService)
    {
        _db = db;
        _totpService = totpService;
    }

    [BindProperty]
    [Required(ErrorMessage = "Code from Authenticator app is required")]
    public string Code { get; set; }

    public string QrUri { get; set; }
    public string Secret { get; set; }

    public async Task<IActionResult> OnGetAsync()
    {
        int? userId = HttpContext.Session.GetInt32("UserId");
        if (userId == null)
        {
            return RedirectToPage("/Account/Login");
        }

        var user = await _db.Users.FindAsync(userId.Value);
        if (user == null)
        {
            return RedirectToPage("/Account/Login");
        }

        if (!string.IsNullOrEmpty(user.TotpSecret))
        {
            Secret = user.TotpSecret;
        }
        else
        {
            var secret = _totpService.GenerateSecret();
            Secret = secret;
            user.TotpSecret = secret;
            await _db.SaveChangesAsync();
        }
        
        QrUri = _totpService.GenerateQrUri(Secret, user.Email, APP_NAME);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        int? userId = HttpContext.Session.GetInt32("UserId");
        if (userId == null)
        {
            return RedirectToPage("/Account/Login");
        }

        var user = await _db.Users.FindAsync(userId.Value);
        if (user == null)
        {
            return RedirectToPage("/Account/Login");
        }
        
        if (_totpService.VerifyCode(user.TotpSecret, Code))
        {
            user.MfaEnabled = true;
            await _db.SaveChangesAsync();
            
            return RedirectToPage("/Index");
        }

        ModelState.AddModelError(string.Empty, "Invalid code");
        return await OnGetAsync();
    }
}

