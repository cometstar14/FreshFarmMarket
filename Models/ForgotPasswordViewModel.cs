using System.ComponentModel.DataAnnotations;

namespace FreshFarmMarket.Models
{
    public class ForgotPasswordViewModel
    {
        [Required(ErrorMessage = "Email Address is required")]
        [EmailAddress(ErrorMessage = "Invalid Email Address")]
        [Display(Name = "Email Address")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Please complete the reCAPTCHA")]
        public string RecaptchaToken { get; set; } = string.Empty;  
    }
}