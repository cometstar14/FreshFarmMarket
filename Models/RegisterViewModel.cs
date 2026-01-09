using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace FreshFarmMarket.Models
{
    public class RegisterViewModel
    {
        [Required(ErrorMessage = "Full Name is required")]
        [StringLength(100)]
        [RegularExpression(@"^[a-zA-Z\s'-]+$", ErrorMessage = "Full Name can only contain letters, spaces, hyphens and apostrophes")]
        [Display(Name = "Full Name")]
        public string FullName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Credit Card Number is required")]
        [RegularExpression(@"^\d{16}$", ErrorMessage = "Credit Card Number must be exactly 16 digits")]
        [Display(Name = "Credit Card Number")]
        public string CreditCardNo { get; set; } = string.Empty;

        [Required(ErrorMessage = "Gender is required")]
        public string Gender { get; set; } = string.Empty;

        [Required(ErrorMessage = "Mobile Number is required")]
        [RegularExpression(@"^[689]\d{7}$", ErrorMessage = "Mobile Number must be 8 digits starting with 6, 8, or 9")]
        [Display(Name = "Mobile Number")]
        public string MobileNo { get; set; } = string.Empty;

        [Required(ErrorMessage = "Delivery Address is required")]
        [StringLength(500)]
        [Display(Name = "Delivery Address")]
        public string DeliveryAddress { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email Address is required")]
        [EmailAddress(ErrorMessage = "Invalid Email Address")]
        [StringLength(100)]
        [Remote(action: "IsEmailAvailable", controller: "Account", ErrorMessage = "Email already exists")]
        [Display(Name = "Email Address")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required")]
        [StringLength(100, MinimumLength = 12)]
        [DataType(DataType.Password)]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^()_+=\[\]{};':""\\|,.<>\/-])[A-Za-z\d@$!%*?&#^()_+=\[\]{};':""\\|,.<>\/-]{12,}$",
            ErrorMessage = "Password must contain uppercase, lowercase, number, and special character")]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "Confirm Password is required")]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Passwords do not match")]
        [Display(Name = "Confirm Password")]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Display(Name = "Profile Photo")]
        public IFormFile? Photo { get; set; }

        [StringLength(1000)]
        [Display(Name = "About Me")]
        public string? AboutMe { get; set; }

        [Required(ErrorMessage = "Please complete the reCAPTCHA")]
        public string RecaptchaToken { get; set; } = string.Empty;
    }
}