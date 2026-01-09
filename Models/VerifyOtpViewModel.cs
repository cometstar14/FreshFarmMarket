using System.ComponentModel.DataAnnotations;

namespace FreshFarmMarket.Models
{
    public class VerifyOtpViewModel
    {
        [Required(ErrorMessage = "Verification code is required")]
        [StringLength(6, MinimumLength = 6, ErrorMessage = "Code must be exactly 6 digits")]
        [RegularExpression(@"^\d{6}$", ErrorMessage = "Code must be 6 digits")]
        [Display(Name = "Verification Code")]
        public string Code { get; set; } = string.Empty;

        [Required]
        public string Email { get; set; } = string.Empty;

        public bool RememberMe { get; set; }
    }
}