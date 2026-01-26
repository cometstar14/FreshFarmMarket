using System.ComponentModel.DataAnnotations;

namespace FreshFarmMarket.Models
{
    public class User
    {
        [Key]
        public int UserId { get; set; }

        [Required]
        [StringLength(100)]
        public string FullName { get; set; } = string.Empty;

        [Required]
        [StringLength(500)]
        public string CreditCardNo { get; set; } = string.Empty;

        [Required]
        public string Gender { get; set; } = string.Empty;

        [Required]
        [StringLength(8)]
        public string MobileNo { get; set; } = string.Empty;

        [Required]
        [StringLength(500)]
        public string DeliveryAddress { get; set; } = string.Empty;

        [Required]
        [EmailAddress]
        [StringLength(100)]
        public string Email { get; set; } = string.Empty;

        [Required]
        [StringLength(500)]
        public string PasswordHash { get; set; } = string.Empty;

        [StringLength(500)]
        public string? Salt { get; set; }

        [StringLength(255)]
        public string? PhotoPath { get; set; }

        [StringLength(1000)]
        public string? AboutMe { get; set; }

        public DateTime CreatedDate { get; set; } = DateTime.Now;

        public DateTime? LastLoginDate { get; set; }

        public int LoginAttempts { get; set; } = 0;

        public DateTime? LockoutEndDate { get; set; }

        public bool IsLocked { get; set; } = false;

        public DateTime? LastPasswordChangeDate { get; set; }

        public DateTime? CannotChangePasswordUntil { get; set; } 

        public bool TwoFactorEnabled { get; set; } = false;
        [StringLength(20)]
        public string? TwoFactorMethod { get; set; } = "SMS";

        [StringLength(500)]
        public string? TwoFactorSecret { get; set; }

        
        [StringLength(100)]
        public string? LastSessionId { get; set; }

        public DateTime? LastSessionActivity { get; set; }

        public virtual ICollection<PasswordHistory> PasswordHistories { get; set; } = new List<PasswordHistory>();

        public virtual ICollection<AuditLog> AuditLogs { get; set; } = new List<AuditLog>();
    }
}