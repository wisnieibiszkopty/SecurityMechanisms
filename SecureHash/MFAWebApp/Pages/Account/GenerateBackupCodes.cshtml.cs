using MFAWebApp.Services.TOTP;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MFAWebApp.Pages.Account;

public class GenerateBackupCodesModel : PageModel
{
    private readonly IBackupCodeService _backupCodeService;

    public GenerateBackupCodesModel(IBackupCodeService backupService)
    {
        _backupCodeService = backupService;
    }

    [BindProperty]
    public IReadOnlyList<string>? Codes { get; set; }

    public int RemainingCodesCount { get; set; }

    public async Task<IActionResult> OnGetAsync()
    {
        int? userId = HttpContext.Session.GetInt32("UserId");
        if (userId == null) return RedirectToPage("/Account/Login");

        RemainingCodesCount = await _backupCodeService.GetRemainingCountAsync(userId.Value);

        return Page();
    }

    public async Task<IActionResult> OnPostGenerateAsync()
    {
        int? userId = HttpContext.Session.GetInt32("UserId");
        if (userId == null) return RedirectToPage("/Account/Login");

        Codes = await _backupCodeService.GenerateNewCodesAsync(userId.Value, count: 10, codeLength: 10);

        return Page();
    }
}
