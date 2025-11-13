using System.ComponentModel.DataAnnotations;

namespace MFAWebApp.Models;

public class BackupCode
{
    [Key]
    public int Id { get; set; }

    [Required]
    public int UserId { get; set; }

    [Required]
    public string CodeHash { get; set; }

    public bool Used { get; set; } = false;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}