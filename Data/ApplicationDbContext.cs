using Microsoft.EntityFrameworkCore;
using FreshFarmMarket.Models;

namespace FreshFarmMarket.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<PasswordHistory> PasswordHistories { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<TwoFactorCode> TwoFactorCodes { get; set; }
        public DbSet<PasswordResetToken> PasswordResetTokens { get; set; }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<User>(entity =>
            {
                entity.HasKey(e => e.UserId);
                entity.HasIndex(e => e.Email).IsUnique();
                entity.Property(e => e.Email).IsRequired();
            });

            modelBuilder.Entity<PasswordHistory>(entity =>
            {
                entity.HasKey(e => e.PasswordHistoryId);
                entity.HasOne(e => e.User)
                    .WithMany(e => e.PasswordHistories)
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            modelBuilder.Entity<AuditLog>(entity =>
            {
                entity.HasKey(e => e.AuditLogId);
                entity.HasOne(e => e.User)
                    .WithMany(e => e.AuditLogs)
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.SetNull);
            });

            modelBuilder.Entity<TwoFactorCode>(entity =>
            {
                entity.HasKey(e => e.TwoFactorCodeId);
                entity.HasOne(e => e.User)
                    .WithMany()
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });
            modelBuilder.Entity<PasswordResetToken>(entity =>
            {
                entity.HasKey(e => e.TokenId);
                entity.HasOne(e => e.User)
                    .WithMany()
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasIndex(e => e.Token).IsUnique(); // Optional: Ensure token uniqueness
                entity.Property(e => e.Token).IsRequired();
                entity.Property(e => e.CreatedDate).IsRequired();
                entity.Property(e => e.ExpirationDate).IsRequired();
            });

        }
    }
}