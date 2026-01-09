using FreshFarmMarket.Data;
using FreshFarmMarket.Models;
using FreshFarmMarket.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;

namespace FreshFarmMarket.Controllers
{
    public class AccountController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IEncryptionService _encryptionService;
        private readonly IAuditService _auditService;
        private readonly IReCaptchaService _reCaptchaService;
        private readonly IConfiguration _configuration;
        private readonly IWebHostEnvironment _env;
        private readonly ISessionTrackingService _sessionTrackingService;
        private readonly IEmailService _emailService;
        private readonly ISmsService _smsService;
        public AccountController(
            ApplicationDbContext context,
            IEncryptionService encryptionService,
            IAuditService auditService,
            IReCaptchaService reCaptchaService,
            IConfiguration configuration,
            IWebHostEnvironment env,
            ISessionTrackingService sessionTrackingService,
            IEmailService emailService,
            ISmsService smsService)
        {
            _context = context;
            _encryptionService = encryptionService;
            _auditService = auditService;
            _reCaptchaService = reCaptchaService;
            _configuration = configuration;
            _env = env;
            _sessionTrackingService = sessionTrackingService;
            _emailService = emailService;
            _smsService = smsService;
        }

        // ========== REGISTRATION ==========
        [HttpGet]
        public IActionResult Register()
        {
            if (IsUserLoggedIn())
                return RedirectToAction("Index", "Home");

            ViewBag.ReCaptchaSiteKey = _configuration["ReCaptcha:SiteKey"];
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            ViewBag.ReCaptchaSiteKey = _configuration["ReCaptcha:SiteKey"];

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // SERVER-SIDE PASSWORD VALIDATION
            var passwordErrors = ValidatePasswordServerSide(model.Password);
            if (passwordErrors.Any())
            {
                foreach (var error in passwordErrors)
                {
                    ModelState.AddModelError("Password", error);
                }
                return View(model);
            }

            var isValidCaptcha = await _reCaptchaService.ValidateTokenAsync(model.RecaptchaToken);
            if (!isValidCaptcha)
            {
                ModelState.AddModelError("", "reCAPTCHA validation failed. Please try again.");
                return View(model);
            }

            if (await _context.Users.AnyAsync(u => u.Email == model.Email))
            {
                ModelState.AddModelError("Email", "Email already exists");
                await _auditService.LogActivityAsync(null, model.Email, "RegistrationFailed", false, "Email already exists", HttpContext);
                return View(model);
            }

            if (model.Photo == null || model.Photo.Length == 0)
            {
                ModelState.AddModelError("Photo", "Photo is required");
                return View(model);
            }

            var allowedExtensions = new[] { ".jpg", ".jpeg" };
            var extension = Path.GetExtension(model.Photo.FileName).ToLowerInvariant();

            if (!allowedExtensions.Any(ext => ext == extension))
            {
                ModelState.AddModelError("Photo", "Only JPG files are allowed");
                return View(model);
            }

            if (model.Photo.Length > 5 * 1024 * 1024)
            {
                ModelState.AddModelError("Photo", "File size must not exceed 5MB");
                return View(model);
            }

            string sanitizedFullName = SanitizeInput(model.FullName);
            string sanitizedDeliveryAddress = SanitizeInput(model.DeliveryAddress);
            string sanitizedAboutMe = SanitizeInput(model.AboutMe);

            string photoPath = await SavePhotoAsync(model.Photo);
            if (string.IsNullOrEmpty(photoPath))
            {
                ModelState.AddModelError("Photo", "Failed to upload photo");
                return View(model);
            }

            try
            {
                string salt;
                string hashedPassword = _encryptionService.HashPassword(model.Password, out salt);
                string encryptedCreditCard = _encryptionService.Encrypt(model.CreditCardNo);

                var user = new User
                {
                    FullName = sanitizedFullName,
                    CreditCardNo = encryptedCreditCard,
                    Gender = model.Gender,
                    MobileNo = model.MobileNo,
                    DeliveryAddress = sanitizedDeliveryAddress,
                    Email = model.Email.ToLower(),
                    PasswordHash = hashedPassword,
                    Salt = salt,
                    PhotoPath = photoPath,
                    AboutMe = sanitizedAboutMe,
                    CreatedDate = DateTime.Now,
                    LastPasswordChangeDate = DateTime.Now,
                    LoginAttempts = 0,
                    IsLocked = false
                };

                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                var passwordHistory = new PasswordHistory
                {
                    UserId = user.UserId,
                    PasswordHash = hashedPassword,
                    Salt = salt,
                    ChangedDate = DateTime.Now
                };
                _context.PasswordHistories.Add(passwordHistory);
                await _context.SaveChangesAsync();

                await _auditService.LogActivityAsync(user.UserId, user.Email, "Registration", true, "User registered successfully", HttpContext);

                TempData["SuccessMessage"] = "Registration successful! Please login.";
                return RedirectToAction("Login");
            }
            catch (Exception ex)
            {
                if (!string.IsNullOrEmpty(photoPath))
                {
                    DeletePhoto(photoPath);
                }

                ModelState.AddModelError("", "An error occurred during registration. Please try again.");
                await _auditService.LogActivityAsync(null, model.Email, "RegistrationFailed", false, ex.Message, HttpContext);
                return View(model);
            }
        }

        // ========== LOGIN ==========
        [HttpGet]
        public IActionResult Login(string? timeout, string? multiple)
        {
            if (IsUserLoggedIn())
                return RedirectToAction("Index", "Home");

            ViewBag.ReCaptchaSiteKey = _configuration["ReCaptcha:SiteKey"];

            // Handle session timeout
            if (timeout == "true")
            {
                TempData["ErrorMessage"] = "Your session has expired due to inactivity. Please login again.";
            }

            // Handle multiple login logout
            if (multiple == "true")
            {
                TempData["ErrorMessage"] = "You were logged out because you logged in from another device or browser.";
            }

            // Check for return URL
            var returnUrl = HttpContext.Session.GetString("ReturnUrl");
            if (!string.IsNullOrEmpty(returnUrl))
            {
                ViewBag.ReturnUrl = returnUrl;
                HttpContext.Session.Remove("ReturnUrl");
            }

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl)
        {
            ViewBag.ReCaptchaSiteKey = _configuration["ReCaptcha:SiteKey"];

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var isValidCaptcha = await _reCaptchaService.ValidateTokenAsync(model.RecaptchaToken);
            if (!isValidCaptcha)
            {
                ModelState.AddModelError("", "reCAPTCHA validation failed. Please try again.");
                return View(model);
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == model.Email.ToLower());

            if (user == null)
            {
                ModelState.AddModelError("", "Invalid email or password");
                await _auditService.LogActivityAsync(null, model.Email, "LoginFailed", false, "User not found", HttpContext);
                return View(model);
            }

            if (user.IsLocked)
            {
                var autoUnlockMinutes = _configuration.GetValue<int>("Security:AutoUnlockMinutes", 15);
                if (user.LockoutEndDate.HasValue && DateTime.Now > user.LockoutEndDate.Value.AddMinutes(autoUnlockMinutes))
                {
                    user.IsLocked = false;
                    user.LoginAttempts = 0;
                    user.LockoutEndDate = null;
                    await _context.SaveChangesAsync();
                }
                else
                {
                    var remainingTime = user.LockoutEndDate.HasValue ?
                        (user.LockoutEndDate.Value.AddMinutes(autoUnlockMinutes) - DateTime.Now).TotalMinutes : 0;

                    ModelState.AddModelError("", $"Account is locked. Please try again in {Math.Ceiling(remainingTime)} minutes.");
                    await _auditService.LogActivityAsync(user.UserId, user.Email, "LoginFailed", false, "Account locked", HttpContext);
                    return View(model);
                }
            }

            if (!_encryptionService.VerifyPassword(model.Password, user.PasswordHash, user.Salt))
            {
                // Check for multiple logins BEFORE creating session
                var activeSessions = _sessionTrackingService.GetActiveSessionCount(user.UserId);

                user.LoginAttempts++;

                var maxAttempts = _configuration.GetValue<int>("Security:MaxLoginAttempts", 3);
                var lockoutDuration = _configuration.GetValue<int>("Security:LockoutDurationMinutes", 10);

                if (user.LoginAttempts >= maxAttempts)
                {
                    user.IsLocked = true;
                    user.LockoutEndDate = DateTime.Now.AddMinutes(lockoutDuration);
                    await _context.SaveChangesAsync();

                    ModelState.AddModelError("", $"Too many failed login attempts. Account locked for {lockoutDuration} minutes.");
                    await _auditService.LogActivityAsync(user.UserId, user.Email, "AccountLocked", true, "Max login attempts exceeded", HttpContext);
                }
                else
                {
                    await _context.SaveChangesAsync();
                    var attemptsLeft = maxAttempts - user.LoginAttempts;
                    ModelState.AddModelError("", $"Invalid email or password. {attemptsLeft} attempts remaining.");
                    await _auditService.LogActivityAsync(user.UserId, user.Email, "LoginFailed", false, "Invalid password", HttpContext);
                }

                return View(model);
            }

            var existingSessionId = HttpContext.Session.GetString("UserId");
            if (!string.IsNullOrEmpty(existingSessionId))
            {
                HttpContext.Session.Clear();
            }

            var maxPasswordAge = _configuration.GetValue<int>("Security:MaxPasswordAgeDays", 90);
            if (user.LastPasswordChangeDate.HasValue &&
                (DateTime.Now - user.LastPasswordChangeDate.Value).TotalDays > maxPasswordAge)
            {
                TempData["WarningMessage"] = "Your password has expired. Please change your password.";
            }

            user.LoginAttempts = 0;
            user.IsLocked = false;
            user.LockoutEndDate = null;
            user.LastLoginDate = DateTime.Now;
            await _context.SaveChangesAsync();

            if (user.TwoFactorEnabled)
            {
                // Generate OTP code
                var code = new Random().Next(100000, 999999).ToString();
                var expirationMinutes = 5;

                var twoFactorCode = new TwoFactorCode
                {
                    UserId = user.UserId,
                    Code = code,
                    CreatedDate = DateTime.Now,
                    ExpirationDate = DateTime.Now.AddMinutes(expirationMinutes),
                    IsUsed = false
                };

                _context.TwoFactorCodes.Add(twoFactorCode);
                await _context.SaveChangesAsync();

                // Send OTP via SMS
                var smsSent = await _smsService.Send2FACodeAsync(user.MobileNo, code);

                if (!smsSent)
                {
                    ModelState.AddModelError("", "Failed to send verification code. Please try again.");
                    await _auditService.LogActivityAsync(user.UserId, user.Email, "LoginFailed", false, "Failed to send 2FA SMS", HttpContext);
                    return View(model);
                }

                await _auditService.LogActivityAsync(user.UserId, user.Email, "Login2FAInitiated", true, "2FA code sent", HttpContext);

                // Redirect to OTP verification
                return RedirectToAction("VerifyOtp", new { email = user.Email, rememberMe = model.RememberMe });
            }

            CreateSession(user);

            await _auditService.LogActivityAsync(user.UserId, user.Email, "Login", true, "Successful login", HttpContext);

            // After successful login:
            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }

            return RedirectToAction("Index", "Home");
        }

        // ========== LOGOUT ==========
        [HttpGet]
        public async Task<IActionResult> Logout()
        {
            var userId = GetCurrentUserId();
            var email = HttpContext.Session.GetString("Email");
            var sessionId = HttpContext.Session.GetString("SessionId");

            // Remove from session tracking
            if (!string.IsNullOrEmpty(sessionId))
            {
                _sessionTrackingService.RemoveSession(sessionId);
            }

            if (userId.HasValue)
            {
                // Clear session ID from database
                var user = await _context.Users.FindAsync(userId.Value);
                if (user != null && user.LastSessionId == sessionId)
                {
                    user.LastSessionId = null;
                    await _context.SaveChangesAsync();
                }

                await _auditService.LogActivityAsync(userId.Value, email, "Logout", true, "User logged out", HttpContext);
            }

            HttpContext.Session.Clear();

            TempData["SuccessMessage"] = "You have been logged out successfully.";
            return RedirectToAction("Login");
        }

        // ========== EMAIL AVAILABILITY CHECK ==========
        [HttpGet]
        public async Task<IActionResult> IsEmailAvailable(string email)
        {
            if (string.IsNullOrEmpty(email))
                return Json(true);

            var exists = await _context.Users.AnyAsync(u => u.Email.ToLower() == email.ToLower());
            return Json(!exists);
        }

        // ========== CHANGE PASSWORD ==========
        [HttpGet]
        public IActionResult ChangePassword()
        {
            if (!IsUserLoggedIn())
                return RedirectToAction("Login");

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!IsUserLoggedIn())
                return RedirectToAction("Login");

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var userId = GetCurrentUserId();
            var user = await _context.Users
                .Include(u => u.PasswordHistories)
                .FirstOrDefaultAsync(u => u.UserId == userId);

            if (user == null)
            {
                return RedirectToAction("Login");
            }

            // Verify current password
            if (!_encryptionService.VerifyPassword(model.CurrentPassword, user.PasswordHash, user.Salt))
            {
                ModelState.AddModelError("CurrentPassword", "Current password is incorrect");
                await _auditService.LogActivityAsync(user.UserId, user.Email, "ChangePasswordFailed", false, "Incorrect current password", HttpContext);
                return View(model);
            }

            // Check minimum password age
            var minPasswordAgeMinutes = _configuration.GetValue<int>("Security:MinPasswordAgeMinutes", 5);
            if (user.LastPasswordChangeDate.HasValue)
            {
                var minutesSinceLastChange = (DateTime.Now - user.LastPasswordChangeDate.Value).TotalMinutes;
                if (minutesSinceLastChange < minPasswordAgeMinutes)
                {
                    var remainingMinutes = Math.Ceiling(minPasswordAgeMinutes - minutesSinceLastChange);
                    ModelState.AddModelError("", $"You cannot change your password yet. Please wait {remainingMinutes} more minutes.");
                    await _auditService.LogActivityAsync(user.UserId, user.Email, "ChangePasswordFailed", false, "Minimum password age not met", HttpContext);
                    return View(model);
                }
            }

            // Check password history (last 2 passwords)
            var passwordHistoryCount = _configuration.GetValue<int>("Security:PasswordHistoryCount", 2);
            var recentPasswords = user.PasswordHistories
                .OrderByDescending(ph => ph.ChangedDate)
                .Take(passwordHistoryCount)
                .ToList();

            foreach (var oldPassword in recentPasswords)
            {
                if (_encryptionService.VerifyPassword(model.NewPassword, oldPassword.PasswordHash, oldPassword.Salt ?? ""))
                {
                    ModelState.AddModelError("NewPassword", $"You cannot reuse your last {passwordHistoryCount} passwords");
                    await _auditService.LogActivityAsync(user.UserId, user.Email, "ChangePasswordFailed", false, "Password reuse detected", HttpContext);
                    return View(model);
                }
            }

            // All checks passed - update password
            string salt;
            string hashedPassword = _encryptionService.HashPassword(model.NewPassword, out salt);

            user.PasswordHash = hashedPassword;
            user.Salt = salt;
            user.LastPasswordChangeDate = DateTime.Now;

            // Add to password history
            var passwordHistory = new PasswordHistory
            {
                UserId = user.UserId,
                PasswordHash = hashedPassword,
                Salt = salt,
                ChangedDate = DateTime.Now
            };
            _context.PasswordHistories.Add(passwordHistory);

            await _context.SaveChangesAsync();
            await _auditService.LogActivityAsync(user.UserId, user.Email, "ChangePassword", true, "Password changed successfully", HttpContext);

            TempData["SuccessMessage"] = "Password changed successfully!";
            return RedirectToAction("Index", "Home");
        }

        // ========== FORGOT PASSWORD ==========
        [HttpGet]
        public IActionResult ForgotPassword()
        {
            if (IsUserLoggedIn())
                return RedirectToAction("Index", "Home");

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == model.Email.ToLower());

            // Always show success message even if email doesn't exist (security best practice)
            if (user == null)
            {
                TempData["SuccessMessage"] = "If an account with that email exists, a password reset link has been sent.";
                await _auditService.LogActivityAsync(null, model.Email, "ForgotPasswordFailed", false, "Email not found", HttpContext);
                return RedirectToAction("Login");
            }

            // Generate reset token
            var resetToken = Guid.NewGuid().ToString();
            var expirationMinutes = 60; // Token valid for 1 hour

            var passwordResetToken = new PasswordResetToken
            {
                UserId = user.UserId,
                Token = resetToken,
                CreatedDate = DateTime.Now,
                ExpirationDate = DateTime.Now.AddMinutes(expirationMinutes),
                IsUsed = false
            };

            _context.PasswordResetTokens.Add(passwordResetToken);
            await _context.SaveChangesAsync();

            // Generate reset link
            var resetLink = Url.Action("ResetPassword", "Account",
                new { token = resetToken, email = user.Email },
                Request.Scheme);

            // Send email
            var emailSent = await _emailService.SendPasswordResetEmailAsync(user.Email, resetLink);

            if (emailSent)
            {
                await _auditService.LogActivityAsync(user.UserId, user.Email, "ForgotPassword", true, "Reset link sent", HttpContext);
                TempData["SuccessMessage"] = "A password reset link has been sent to your email address.";
            }
            else
            {
                await _auditService.LogActivityAsync(user.UserId, user.Email, "ForgotPasswordFailed", false, "Email sending failed", HttpContext);
                TempData["ErrorMessage"] = "Failed to send reset email. Please try again later.";
            }

            return RedirectToAction("Login");
        }

        // ========== RESET PASSWORD ==========
        [HttpGet]
        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(email))
            {
                TempData["ErrorMessage"] = "Invalid password reset link.";
                return RedirectToAction("Login");
            }

            // Verify token exists and is valid
            var resetToken = await _context.PasswordResetTokens
                .Include(rt => rt.User)
                .FirstOrDefaultAsync(rt => rt.Token == token && rt.User.Email == email.ToLower());

            if (resetToken == null)
            {
                TempData["ErrorMessage"] = "Invalid password reset link.";
                return RedirectToAction("Login");
            }

            if (resetToken.IsUsed)
            {
                TempData["ErrorMessage"] = "This password reset link has already been used.";
                return RedirectToAction("Login");
            }

            if (DateTime.Now > resetToken.ExpirationDate)
            {
                TempData["ErrorMessage"] = "This password reset link has expired. Please request a new one.";
                return RedirectToAction("ForgotPassword");
            }

            // Token is valid - show reset form
            var model = new ResetPasswordViewModel
            {
                Token = token,
                Email = email
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Verify token again
            var resetToken = await _context.PasswordResetTokens
                .Include(rt => rt.User)
                .FirstOrDefaultAsync(rt => rt.Token == model.Token && rt.User.Email == model.Email.ToLower());

            if (resetToken == null || resetToken.IsUsed || DateTime.Now > resetToken.ExpirationDate)
            {
                ModelState.AddModelError("", "Invalid or expired reset link.");
                return View(model);
            }

            var user = resetToken.User;

            // Check password history (last 2 passwords)
            var passwordHistoryCount = _configuration.GetValue<int>("Security:PasswordHistoryCount", 2);
            var recentPasswords = await _context.PasswordHistories
                .Where(ph => ph.UserId == user.UserId)
                .OrderByDescending(ph => ph.ChangedDate)
                .Take(passwordHistoryCount)
                .ToListAsync();

            foreach (var oldPassword in recentPasswords)
            {
                if (_encryptionService.VerifyPassword(model.NewPassword, oldPassword.PasswordHash, oldPassword.Salt ?? ""))
                {
                    ModelState.AddModelError("NewPassword", $"You cannot reuse your last {passwordHistoryCount} passwords");
                    await _auditService.LogActivityAsync(user.UserId, user.Email, "ResetPasswordFailed", false, "Password reuse detected", HttpContext);
                    return View(model);
                }
            }

            // All checks passed - update password
            string salt;
            string hashedPassword = _encryptionService.HashPassword(model.NewPassword, out salt);

            user.PasswordHash = hashedPassword;
            user.Salt = salt;
            user.LastPasswordChangeDate = DateTime.Now;
            user.LoginAttempts = 0;
            user.IsLocked = false;
            user.LockoutEndDate = null;

            // Mark token as used
            resetToken.IsUsed = true;
            resetToken.UsedDate = DateTime.Now;

            // Add to password history
            var passwordHistory = new PasswordHistory
            {
                UserId = user.UserId,
                PasswordHash = hashedPassword,
                Salt = salt,
                ChangedDate = DateTime.Now
            };
            _context.PasswordHistories.Add(passwordHistory);

            await _context.SaveChangesAsync();
            await _auditService.LogActivityAsync(user.UserId, user.Email, "ResetPassword", true, "Password reset successfully", HttpContext);

            TempData["SuccessMessage"] = "Your password has been reset successfully! Please login with your new password.";
            return RedirectToAction("Login");
        }

        // ========== TWO-FACTOR AUTHENTICATION ==========
        [HttpGet]
        public async Task<IActionResult> Enable2FA()
        {
            if (!IsUserLoggedIn())
                return RedirectToAction("Login");

            var userId = GetCurrentUserId();
            var user = await _context.Users.FindAsync(userId.Value);

            if (user == null)
                return RedirectToAction("Login");

            ViewBag.User = user;
            return View(new Enable2FAViewModel { MobileNo = user.MobileNo });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Enable2FA(Enable2FAViewModel model)
        {
            if (!IsUserLoggedIn())
                return RedirectToAction("Login");

            if (!ModelState.IsValid)
            {
                var userId = GetCurrentUserId();
                var userForView = await _context.Users.FindAsync(userId.Value);
                ViewBag.User = userForView;
                return View(model);
            }

            var user = await _context.Users.FindAsync(GetCurrentUserId().Value);
            if (user == null)
                return RedirectToAction("Login");

            // Verify the code
            var recentCode = await _context.TwoFactorCodes
                .Where(tc => tc.UserId == user.UserId && !tc.IsUsed)
                .OrderByDescending(tc => tc.CreatedDate)
                .FirstOrDefaultAsync();

            if (recentCode == null || recentCode.Code != model.VerificationCode)
            {
                ModelState.AddModelError("VerificationCode", "Invalid verification code");
                ViewBag.User = user;
                return View(model);
            }

            if (DateTime.Now > recentCode.ExpirationDate)
            {
                ModelState.AddModelError("VerificationCode", "Verification code has expired");
                ViewBag.User = user;
                return View(model);
            }

            // Enable 2FA
            user.TwoFactorEnabled = true;
            user.MobileNo = model.MobileNo;
            recentCode.IsUsed = true;
            recentCode.UsedDate = DateTime.Now;

            await _context.SaveChangesAsync();
            await _auditService.LogActivityAsync(user.UserId, user.Email, "Enable2FA", true, "Two-Factor Authentication enabled", HttpContext);

            TempData["SuccessMessage"] = "Two-Factor Authentication has been enabled successfully!";
            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Disable2FA()
        {
            if (!IsUserLoggedIn())
                return RedirectToAction("Login");

            var userId = GetCurrentUserId();
            var user = await _context.Users.FindAsync(userId.Value);

            if (user == null)
                return RedirectToAction("Login");

            user.TwoFactorEnabled = false;
            await _context.SaveChangesAsync();
            await _auditService.LogActivityAsync(user.UserId, user.Email, "Disable2FA", true, "Two-Factor Authentication disabled", HttpContext);

            TempData["SuccessMessage"] = "Two-Factor Authentication has been disabled.";
            return RedirectToAction("Enable2FA");
        }

        [HttpPost]
        public async Task<IActionResult> SendVerificationCode([FromBody] SendCodeRequest request)
        {
            if (!IsUserLoggedIn())
                return Unauthorized();

            var userId = GetCurrentUserId();
            var user = await _context.Users.FindAsync(userId.Value);

            if (user == null)
                return NotFound();

            // Generate 6-digit code
            var code = new Random().Next(100000, 999999).ToString();
            var expirationMinutes = 5;

            var twoFactorCode = new TwoFactorCode
            {
                UserId = user.UserId,
                Code = code,
                CreatedDate = DateTime.Now,
                ExpirationDate = DateTime.Now.AddMinutes(expirationMinutes),
                IsUsed = false
            };

            _context.TwoFactorCodes.Add(twoFactorCode);
            await _context.SaveChangesAsync();

            // Send SMS
            var smsSent = await _smsService.Send2FACodeAsync(request.MobileNo, code);

            if (smsSent)
            {
                await _auditService.LogActivityAsync(user.UserId, user.Email, "SendVerificationCode", true, "Verification code sent", HttpContext);
                return Ok();
            }
            else
            {
                await _auditService.LogActivityAsync(user.UserId, user.Email, "SendVerificationCodeFailed", false, "Failed to send SMS", HttpContext);
                return StatusCode(500);
            }
        }

        [HttpGet]
        public async Task<IActionResult> VerifyOtp(string email, bool rememberMe = false)
        {
            var model = new VerifyOtpViewModel
            {
                Email = email,
                RememberMe = rememberMe
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyOtp(VerifyOtpViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == model.Email.ToLower());

            if (user == null)
            {
                ModelState.AddModelError("", "Invalid verification attempt");
                return View(model);
            }

            // Verify the code
            var recentCode = await _context.TwoFactorCodes
                .Where(tc => tc.UserId == user.UserId && !tc.IsUsed)
                .OrderByDescending(tc => tc.CreatedDate)
                .FirstOrDefaultAsync();

            if (recentCode == null || recentCode.Code != model.Code)
            {
                ModelState.AddModelError("Code", "Invalid verification code");
                await _auditService.LogActivityAsync(user.UserId, user.Email, "VerifyOtpFailed", false, "Invalid OTP code", HttpContext);
                return View(model);
            }

            if (DateTime.Now > recentCode.ExpirationDate)
            {
                ModelState.AddModelError("Code", "Verification code has expired. Please request a new one.");
                await _auditService.LogActivityAsync(user.UserId, user.Email, "VerifyOtpFailed", false, "Expired OTP code", HttpContext);
                return View(model);
            }

            // Mark code as used
            recentCode.IsUsed = true;
            recentCode.UsedDate = DateTime.Now;
            await _context.SaveChangesAsync();

            // Create session (complete login)
            CreateSession(user);

            await _auditService.LogActivityAsync(user.UserId, user.Email, "VerifyOtp", true, "2FA verification successful", HttpContext);

            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        public async Task<IActionResult> ResendOtp(string email)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email.ToLower());

            if (user == null)
            {
                TempData["ErrorMessage"] = "Unable to resend code. Please try logging in again.";
                return RedirectToAction("Login");
            }

            // Generate new code
            var code = new Random().Next(100000, 999999).ToString();
            var expirationMinutes = 5;

            var twoFactorCode = new TwoFactorCode
            {
                UserId = user.UserId,
                Code = code,
                CreatedDate = DateTime.Now,
                ExpirationDate = DateTime.Now.AddMinutes(expirationMinutes),
                IsUsed = false
            };

            _context.TwoFactorCodes.Add(twoFactorCode);
            await _context.SaveChangesAsync();

            // Send SMS
            var smsSent = await _smsService.Send2FACodeAsync(user.MobileNo, code);

            if (smsSent)
            {
                await _auditService.LogActivityAsync(user.UserId, user.Email, "ResendOtp", true, "OTP code resent", HttpContext);
                TempData["SuccessMessage"] = "A new verification code has been sent to your mobile number.";
            }
            else
            {
                await _auditService.LogActivityAsync(user.UserId, user.Email, "ResendOtpFailed", false, "Failed to send SMS", HttpContext);
                TempData["ErrorMessage"] = "Failed to send verification code. Please try again.";
            }

            return RedirectToAction("VerifyOtp", new { email = email });
        }

        // Helper class for SendVerificationCode
        public class SendCodeRequest
        {
            public string MobileNo { get; set; } = string.Empty;
        }

        // ========== PASSWORD VALIDATION METHOD ==========
        private List<string> ValidatePasswordServerSide(string password)
        {
            var errors = new List<string>();

            if (string.IsNullOrEmpty(password))
            {
                errors.Add("Password is required");
                return errors;
            }

            // Check length
            if (password.Length < 12)
                errors.Add("Password must be at least 12 characters");

            // Check lowercase
            if (!Regex.IsMatch(password, "[a-z]"))
                errors.Add("Password must contain at least one lowercase letter (a-z)");

            // Check uppercase
            if (!Regex.IsMatch(password, "[A-Z]"))
                errors.Add("Password must contain at least one uppercase letter (A-Z)");

            // Check number
            if (!Regex.IsMatch(password, @"\d"))
                errors.Add("Password must contain at least one number (0-9)");

            // Check special character
            if (!Regex.IsMatch(password, @"[@$!%*?&#^()_+=\[\]{};':""\\|,.<>\/-]"))
                errors.Add("Password must contain at least one special character (e.g., @$!%*?&)");

            return errors;
        }

        // ========== HELPER METHODS ==========
        private bool IsUserLoggedIn()
        {
            return HttpContext.Session.GetInt32("UserId").HasValue;
        }

        private int? GetCurrentUserId()
        {
            return HttpContext.Session.GetInt32("UserId");
        }

        private void CreateSession(User user)
        {
            // Clear any existing session first
            HttpContext.Session.Clear();

            // Check if user is already logged in elsewhere
            var existingSessions = _sessionTrackingService.GetActiveSessionCount(user.UserId);

            if (existingSessions > 0)
            {
                // Clear old sessions (force logout from other devices)
                _sessionTrackingService.ClearAllUserSessions(user.UserId);

                // Log this security event
                _auditService.LogActivityAsync(user.UserId, user.Email,
                    "MultipleLogin", true,
                    $"User logged in from new device/browser. {existingSessions} previous sessions terminated.",
                    HttpContext);

                TempData["InfoMessage"] = $"You were logged out from {existingSessions} other device(s).";
            }
            HttpContext.Session.SetInt32("UserId", user.UserId);
            HttpContext.Session.SetString("Email", user.Email);
            HttpContext.Session.SetString("FullName", user.FullName);
            HttpContext.Session.SetString("SessionId", Guid.NewGuid().ToString());
            HttpContext.Session.SetString("UserRole", "Member");
            HttpContext.Session.SetString("PhotoPath", user.PhotoPath ?? "");

            // Generate unique session ID
            var sessionId = Guid.NewGuid().ToString();
            HttpContext.Session.SetString("SessionId", sessionId);

            // CRITICAL: Set session activity timestamps
            HttpContext.Session.SetString("SessionCreated", DateTime.UtcNow.ToString("o"));
            HttpContext.Session.SetString("LastActivity", DateTime.UtcNow.ToString("o"));

            // Register this session in the tracking service
            _sessionTrackingService.AddSession(sessionId, user.UserId);

            // Update last login
            user.LastLoginDate = DateTime.Now;

            // Store session ID in database for multiple login detection
            user.LastSessionId = HttpContext.Session.GetString("SessionId");
            _context.SaveChanges();
        }

        private async Task<string> SavePhotoAsync(IFormFile photo)
        {
            try
            {
                var uploadsFolder = Path.Combine(_env.WebRootPath, "uploads");
                if (!Directory.Exists(uploadsFolder))
                {
                    Directory.CreateDirectory(uploadsFolder);
                }

                var uniqueFileName = Guid.NewGuid().ToString() + Path.GetExtension(photo.FileName);
                var filePath = Path.Combine(uploadsFolder, uniqueFileName);

                using (var fileStream = new FileStream(filePath, FileMode.Create))
                {
                    await photo.CopyToAsync(fileStream);
                }

                return "/uploads/" + uniqueFileName;
            }
            catch
            {
                return string.Empty;
            }
        }

        private void DeletePhoto(string photoPath)
        {
            try
            {
                var fullPath = Path.Combine(_env.WebRootPath, photoPath.TrimStart('/'));
                if (System.IO.File.Exists(fullPath))
                {
                    System.IO.File.Delete(fullPath);
                }
            }
            catch
            {
                // Silent fail - photo cleanup is not critical
            }
        }

        private string SanitizeInput(string input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            return System.Net.WebUtility.HtmlEncode(input);
        }
    }
}