using MFAWebApp.Models;
using Microsoft.EntityFrameworkCore;

namespace MFAWebApp.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options): DbContext(options)
{
    public DbSet<User> Users { get; set; }
    public DbSet<BackupCode> BackupCodes { get; set; }
}