using System.ComponentModel.DataAnnotations;

namespace FreshFarmMarket.Models
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "Email Address is required")]
        [EmailAddress(ErrorMessage = "Invalid Email Address")]
        [Display(Name = "Email Address")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Display(Name = "Remember Me")]
        public bool RememberMe { get; set; }

        [Required(ErrorMessage = "Please complete the reCAPTCHA")]
        public string RecaptchaToken { get; set; } = string.Empty;
    }
}