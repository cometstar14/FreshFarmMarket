using System.ComponentModel.DataAnnotations;

namespace FreshFarmMarket.Models
{
    public class Enable2FAViewModel
    {
        [Display(Name = "Enable Two-Factor Authentication")]
        public bool Enable2FA { get; set; }

        [Required(ErrorMessage = "Mobile number is required for 2FA")]
        [RegularExpression(@"^[689]\d{7}$", ErrorMessage = "Mobile Number must be 8 digits starting with 6, 8, or 9")]
        [Display(Name = "Mobile Number")]
        public string MobileNo { get; set; } = string.Empty;

        [Required(ErrorMessage = "Verification code is required")]
        [StringLength(6, MinimumLength = 6, ErrorMessage = "Code must be exactly 6 digits")]
        [RegularExpression(@"^\d{6}$", ErrorMessage = "Code must be 6 digits")]
        [Display(Name = "Verification Code")]
        public string VerificationCode { get; set; } = string.Empty;
    }
}