using MFAWebApp.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MFAWebApp.Pages.Account;

public class ManageModel : PageModel
{
    private readonly AppDbContext _db;

    public ManageModel(AppDbContext db)
    {
        _db = db;
    }

    public bool MfaEnabled { get; set; }

    public async Task<IActionResult> OnGetAsync()
    {
        int? userId = HttpContext.Session.GetInt32("UserId");
        if (userId == null)
            return RedirectToPage("/Account/Login");

        var user = await _db.Users.FindAsync(userId);
        if (user == null)
            return RedirectToPage("/Account/Login");

        MfaEnabled = user.MfaEnabled;

        return Page();
    }

    public async Task<IActionResult> OnPostDisableMfaAsync()
    {
        int? userId = HttpContext.Session.GetInt32("UserId");
        if (userId == null)
            return RedirectToPage("/Account/Login");

        var user = await _db.Users.FindAsync(userId.Value);
        if (user == null)
            return RedirectToPage("/Account/Login");

        user.MfaEnabled = false;
        user.TotpSecret = null;

        await _db.SaveChangesAsync();

        TempData["StatusMessage"] = "MFA disabled";
        return RedirectToPage();
    }
}
