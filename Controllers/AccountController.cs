using FreshFarmMarket.Data;
using FreshFarmMarket.Models;
using FreshFarmMarket.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Runtime.InteropServices;
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
        private readonly ILogger<AccountController> _logger;

        public AccountController(
            ApplicationDbContext context,
            IEncryptionService encryptionService,
            IAuditService auditService,
            IReCaptchaService reCaptchaService,
            IConfiguration configuration,
            IWebHostEnvironment env,
            ISessionTrackingService sessionTrackingService,
            IEmailService emailService,
            ISmsService smsService,
            ILogger<AccountController> logger)
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
            _logger = logger;
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
                await LogAuditAsync(null, "RegistrationFailed", false, "Email already exists");
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

                await LogAuditAsync(user.UserId, "Registration", true, "User registered successfully");

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
                await LogAuditAsync(null, "RegistrationFailed", false, "Registration error occurred");
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

            // TEMPORARY: Comment out reCAPTCHA to test if it's the issue
            // var isValidCaptcha = await _reCaptchaService.ValidateTokenAsync(model.RecaptchaToken);
            var isValidCaptcha = true; // Force true for testing

            if (!isValidCaptcha)
            {
                ModelState.AddModelError("", "reCAPTCHA validation failed. Please try again.");
                return View(model);
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == model.Email.ToLower());

            if (user == null)
            {
                ModelState.AddModelError("", "Invalid email or password");
                await LogAuditAsync(null, "LoginFailed", false, "User not found");
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
                    await LogAuditAsync(user.UserId, "LoginFailed", false, "Account locked");
                    return View(model);
                }
            }


            if (!_encryptionService.VerifyPassword(model.Password, user.PasswordHash, user.Salt))
            {


                user.LoginAttempts++;

                var maxAttempts = _configuration.GetValue<int>("Security:MaxLoginAttempts", 3);
                var lockoutDuration = _configuration.GetValue<int>("Security:LockoutDurationMinutes", 10);

                if (user.LoginAttempts >= maxAttempts)
                {
                    user.IsLocked = true;
                    user.LockoutEndDate = DateTime.Now.AddMinutes(lockoutDuration);
                    await _context.SaveChangesAsync();

                    ModelState.AddModelError("", $"Too many failed login attempts. Account locked for {lockoutDuration} minutes.");
                    await LogAuditAsync(user.UserId, "AccountLocked", true, "Max login attempts exceeded");
                }
                else
                {
                    await _context.SaveChangesAsync();
                    var attemptsLeft = maxAttempts - user.LoginAttempts;
                    ModelState.AddModelError("", $"Invalid email or password. {attemptsLeft} attempts remaining.");
                    await LogAuditAsync(user.UserId, "LoginFailed", false, "Invalid password");
                }

                return View(model);
            }

            var existingSessionCount = _sessionTrackingService.GetActiveSessionCount(user.UserId);

            if (existingSessionCount > 0)
            {
                // Clear all existing sessions for this user
                _sessionTrackingService.ClearAllUserSessions(user.UserId);

                // Update database to clear old session ID
                user.LastSessionId = null;
                await _context.SaveChangesAsync();

                // Log the security event
                await LogAuditAsync(
    user.UserId,
    "MultipleLoginPrevented",
    true,
    $"Cleared {existingSessionCount} existing session(s) from another location"
);

                TempData["InfoMessage"] = $"You were logged out from {existingSessionCount} other device(s).";
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

            //2FA CHECK
            if (user.TwoFactorEnabled)
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

                    // Send OTP via user's preferred method
                    bool codeSent = false;
                    string destination = "";

                    if (user.TwoFactorMethod == "Email")
                    {
                        codeSent = await _emailService.Send2FACodeAsync(user.Email, code);
                        destination = "your email";
                        await LogAuditAsync(user.UserId, "Login2FAInitiated", true, "2FA code sent via Email");
                    }
                    else // Default to SMS
                    {
                        codeSent = await _smsService.Send2FACodeAsync(user.MobileNo, code);
                        destination = "your mobile number";
                        await LogAuditAsync(user.UserId, "Login2FAInitiated", true, "2FA code sent via SMS");
                    }

                    if (!codeSent)
                    {
                        ModelState.AddModelError("", "Failed to send verification code. Please try again.");
                        await LogAuditAsync(user.UserId, "Login2FAFailed", false, "Failed to send 2FA code");
                        return View(model);
                    }

                    // Store temporary data for VerifyOtp page
                    HttpContext.Session.SetInt32("TempUserId", user.UserId);
                    HttpContext.Session.SetString("TempEmail", user.Email);
                    HttpContext.Session.SetString("TempRememberMe", model.RememberMe.ToString());

                    // Commit session
                    await HttpContext.Session.CommitAsync();

                    TempData["InfoMessage"] = $"A verification code has been sent to {destination}.";
                    return RedirectToAction("VerifyOtp");
                }

            CreateSession(user);

            await LogAuditAsync(user.UserId, "Login", true, "Successful login");

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
            var tabId = HttpContext.Session.GetString("TabId");

            // Remove BOTH keys from session tracking (composite and simple)
            if (!string.IsNullOrEmpty(sessionId))
            {
                // Remove composite key if TabId exists
                if (!string.IsNullOrEmpty(tabId))
                {
                    var compositeKey = $"{sessionId}_{tabId}";
                    _sessionTrackingService.RemoveSession(compositeKey);
                }

                // Also remove plain SessionId key
                _sessionTrackingService.RemoveSession(sessionId);
            }

            if (userId.HasValue)
            {
                // Clear session ID from database only if this was the last active session
                var user = await _context.Users.FindAsync(userId.Value);
                if (user != null)
                {
                    var remainingSessions = _sessionTrackingService.GetActiveSessionCount(userId.Value);
                    if (remainingSessions == 0)
                    {
                        user.LastSessionId = null;
                        await _context.SaveChangesAsync();
                    }
                }

                await LogAuditAsync(userId.Value, "Logout", true, "User logged out");
            }

            HttpContext.Session.Clear();

            TempData["SuccessMessage"] = "You have been logged out successfully.";
            return RedirectToAction("Login");
        }

        // ========== EMAIL AVAILABILITY CHECK ==========
        [HttpGet]
        [ValidateAntiForgeryToken]
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
                await LogAuditAsync(user.UserId, "ChangePasswordFailed", false, "Incorrect current password");
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
                    await LogAuditAsync(user.UserId, "ChangePasswordFailed", false, "Minimum password age not met");
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
                    await LogAuditAsync(user.UserId, "ChangePasswordFailed", false, "Password reuse detected");
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
            await LogAuditAsync(user.UserId, "ChangePassword", true, "Password changed successfully");
            TempData["SuccessMessage"] = "Password changed successfully!";
            return RedirectToAction("Index", "Home");
        }

        // ========== FORGOT PASSWORD ==========
        [HttpGet]
        public IActionResult ForgotPassword()
        {
            if (IsUserLoggedIn())
                return RedirectToAction("Index", "Home");

            
            ViewBag.ReCaptchaSiteKey = _configuration["ReCaptcha:SiteKey"];

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {

            // ✅ MINIMAL LOGGING -Don't log user input at all
            _logger.LogInformation("Forgot password request received");

            // Don't log the email or recaptcha token details
            _logger.LogInformation("Model validation status: {IsValid}", ModelState.IsValid);

            if (!ModelState.IsValid)
            {
                _logger.LogInformation("Model validation failed");
                ViewBag.ReCaptchaSiteKey = _configuration["ReCaptcha:SiteKey"];
                return View(model);
            }
            // ⭐ ADD THIS LINE
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

            // Always show success message even if email doesn't exist (security best practice)
            if (user == null)
            {
                TempData["SuccessMessage"] = "If an account with that email exists, a password reset link has been sent.";
                await LogAuditAsync(null, "ForgotPasswordFailed", false, "Email not found");
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
                await LogAuditAsync(user.UserId, "ForgotPassword", true, "Password reset link sent");
                TempData["SuccessMessage"] = "A password reset link has been sent to your email address.";
            }
            else
            {
                await LogAuditAsync(user.UserId, "ForgotPasswordFailed", false, "Email sending failed");
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
                    await LogAuditAsync(user.UserId, "ResetPasswordFailed", false, "Password reuse detected");
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
            await LogAuditAsync(user.UserId, "ResetPassword", true, "Password reset successfully");

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

            // Enable 2FA with selected method
            user.TwoFactorEnabled = true;
            user.TwoFactorMethod = model.TwoFactorMethod; // ← NEW: Save the method

            // Only update mobile number if SMS is chosen
            if (model.TwoFactorMethod == "SMS")
            {
                user.MobileNo = model.MobileNo;
            }

            recentCode.IsUsed = true;
            recentCode.UsedDate = DateTime.Now;

            await _context.SaveChangesAsync();
            await LogAuditAsync(user.UserId, "Enable2FA", true,
            $"Two-Factor Authentication enabled via {model.TwoFactorMethod}");

            TempData["SuccessMessage"] = $"Two-Factor Authentication has been enabled successfully via {model.TwoFactorMethod}!";
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
            await LogAuditAsync(user.UserId, "Disable2FA", true, "Two-Factor Authentication disabled");

            TempData["SuccessMessage"] = "Two-Factor Authentication has been disabled.";
            return RedirectToAction("Enable2FA");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SendVerificationCode([FromBody] SendCodeRequest request)
        {
            try
            {
                if (!IsUserLoggedIn())
                    return Unauthorized(new { error = "Please log in first" });

                var userId = GetCurrentUserId();
                var user = await _context.Users.FindAsync(userId.Value);

                if (user == null)
                    return NotFound(new { error = "User not found" });

                // Validate based on method
                if (request.Method == "SMS")
                {
                    if (string.IsNullOrEmpty(request.MobileNo) || !Regex.IsMatch(request.MobileNo, @"^[689]\d{7}$"))
                    {
                        return BadRequest(new { error = "Please enter a valid Singapore mobile number (8 digits starting with 6, 8, or 9)" });
                    }
                }

                // Generate 6-digit code
                var code = new Random().Next(100000, 999999).ToString();
                var expirationMinutes = 5;

                // Save to database
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

                // Send code based on method
                bool sent = false;
                string destination = "";

                if (request.Method == "Email")
                {
                    sent = await _emailService.Send2FACodeAsync(user.Email, code);
                    destination = user.Email;

                    await LogAuditAsync(
                        user.UserId,
                        "SendVerificationCode",
                        true,
                        "Email verification code sent"
                    );
                }
                else // SMS
                {
                    sent = await _smsService.Send2FACodeAsync(request.MobileNo, code);
                    destination = request.MobileNo;

                    await LogAuditAsync(
                        user.UserId,
                        "SendVerificationCode",
                        true,
                        "SMS verification code sent"
                    );
                }
                return Ok(new
                {
                    success = true,
                    message = $"Verification code sent successfully via {request.Method}!",
                    code = code, // Include for testing
                    hint = request.Method == "SMS"
                        ? "Check the console output or Logs/latest_verification_code.txt for the code"
                        : "Check your email inbox (and spam folder)"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in SendVerificationCode");
                return StatusCode(500, new
                {
                    error = "An unexpected error occurred",
                    details = ex.Message
                });
            }
        }
        [HttpGet]
        public async Task<IActionResult> VerifyOtp()
        {
            // Try to get the temporary user ID from session
            var tempUserId = HttpContext.Session.GetInt32("TempUserId");
            var tempEmail = HttpContext.Session.GetString("TempEmail");

            if (!tempUserId.HasValue || string.IsNullOrEmpty(tempEmail))
            {
                // No pending 2FA verification found
                TempData["ErrorMessage"] = "No pending 2FA verification found. Please login again.";
                await LogAuditAsync(null, "VerifyOtpAccess", false, "No pending 2FA session");
                return RedirectToAction("Login");
            }

            // Get user from database to verify they exist and have 2FA enabled
            var user = await _context.Users.FindAsync(tempUserId.Value);

            if (user == null || !user.TwoFactorEnabled)
            {
                // Clear invalid session data
                HttpContext.Session.Remove("TempUserId");
                HttpContext.Session.Remove("TempEmail");
                HttpContext.Session.Remove("TempRememberMe");

                TempData["ErrorMessage"] = "Invalid verification session. Please login again.";
                return RedirectToAction("Login");
            }

            // Get RememberMe preference
            var rememberMeStr = HttpContext.Session.GetString("TempRememberMe");
            var rememberMe = bool.TryParse(rememberMeStr, out var rm) && rm;

            var model = new VerifyOtpViewModel
            {
                Email = user.Email,
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

            // Get the temporary user ID from session
            var tempUserId = HttpContext.Session.GetInt32("TempUserId");
            var tempEmail = HttpContext.Session.GetString("TempEmail");

            if (!tempUserId.HasValue || string.IsNullOrEmpty(tempEmail))
            {
                ModelState.AddModelError("", "Session expired. Please login again.");
                return RedirectToAction("Login");
            }

            var user = await _context.Users.FindAsync(tempUserId.Value);

            if (user == null)
            {
                ModelState.AddModelError("", "Invalid verification attempt");
                await LogAuditAsync(null, "VerifyOtpFailed", false, "User not found");
                return RedirectToAction("Login");
            }

            // Verify the code
            var recentCode = await _context.TwoFactorCodes
                .Where(tc => tc.UserId == user.UserId && !tc.IsUsed)
                .OrderByDescending(tc => tc.CreatedDate)
                .FirstOrDefaultAsync();

            if (recentCode == null || recentCode.Code != model.Code)
            {
                ModelState.AddModelError("Code", "Invalid verification code");
                await LogAuditAsync(user.UserId, "VerifyOtpFailed", false, "Invalid OTP code");
                return View(model);
            }

            if (DateTime.Now > recentCode.ExpirationDate)
            {
                ModelState.AddModelError("Code", "Verification code has expired. Please request a new one."); 
                        
                return View(model);
            }

            // Mark code as used
            recentCode.IsUsed = true;
            recentCode.UsedDate = DateTime.Now;
            await _context.SaveChangesAsync();

            // Clear the temporary 2FA session data
            HttpContext.Session.Remove("TempUserId");
            HttpContext.Session.Remove("TempEmail");
            HttpContext.Session.Remove("TempRememberMe");

            // Create full session (complete login)
            CreateSession(user);

            await LogAuditAsync(user.UserId, "VerifyOtp", true, "2FA verification successful");

            TempData["SuccessMessage"] = "Login successful!";
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

            // Send via user's preferred method
            bool codeSent = false;
            string destination = "";

            if (user.TwoFactorMethod == "Email")
            {
                codeSent = await _emailService.Send2FACodeAsync(user.Email, code);
                destination = "your email";
            }
            else // SMS
            {
                codeSent = await _smsService.Send2FACodeAsync(user.MobileNo, code);
                destination = "your mobile number";
            }

            if (codeSent)
            {
                await LogAuditAsync(user.UserId, "ResendOtp", true,
                    $"OTP code resent via {user.TwoFactorMethod}");
                TempData["SuccessMessage"] = $"A new verification code has been sent to {destination}.";
            }
            else
            {
                await LogAuditAsync(user.UserId, "ResendOtpFailed", false,
                    "Failed to send verification code");
                TempData["ErrorMessage"] = "Failed to send verification code. Please try again.";
            }

            return RedirectToAction("VerifyOtp", new { email = email });
        }

        // Helper class for SendVerificationCode
        public class SendCodeRequest
        {
            public string MobileNo { get; set; } = string.Empty;
            public string Method { get; set; } = "SMS"; // "SMS" or "Email"
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

            // Get the TabId from the request header (sent by JavaScript)
            var tabIdFromHeader = HttpContext.Request.Headers["X-Tab-Id"].ToString();

            // Use TabId from header if available, otherwise generate one
            // This ensures backward compatibility for browsers without JavaScript
            var tabId = !string.IsNullOrEmpty(tabIdFromHeader)
                ? tabIdFromHeader
                : Guid.NewGuid().ToString();

            // Check if user is already logged in elsewhere (any tab/browser)
            var existingSessions = _sessionTrackingService.GetActiveSessionCount(user.UserId);

            if (existingSessions > 0)
            {
                // Clear ALL old sessions (from all tabs and browsers)
                _sessionTrackingService.ClearAllUserSessions(user.UserId);

                // Log this security event
                _auditService.LogActivityAsync(user.UserId, user.Email,
                    "MultipleLogin", true,
                    $"User logged in from new tab/browser. {existingSessions} previous sessions terminated.",
                    HttpContext);

                TempData["InfoMessage"] = $"You were logged out from {existingSessions} other device(s) or tab(s).";
            }

            // Generate unique session ID (ONLY ONCE!)
            var sessionId = Guid.NewGuid().ToString();

            // Set all session values FIRST
            HttpContext.Session.SetInt32("UserId", user.UserId);
            HttpContext.Session.SetString("Email", user.Email);
            HttpContext.Session.SetString("FullName", user.FullName);
            HttpContext.Session.SetString("SessionId", sessionId);
            HttpContext.Session.SetString("TabId", tabId); // Store TabId in session
            HttpContext.Session.SetString("UserRole", "Member");
            HttpContext.Session.SetString("PhotoPath", user.PhotoPath ?? "");

            // CRITICAL: Set session activity timestamps
            HttpContext.Session.SetString("SessionCreated", DateTime.UtcNow.ToString("o"));
            HttpContext.Session.SetString("LastActivity", DateTime.UtcNow.ToString("o"));

            // IMPORTANT: Register BOTH keys in session tracking for maximum compatibility
            // 1. Register composite key (SessionId_TabId) for tab-specific tracking
            var compositeKey = $"{sessionId}_{tabId}";
            _sessionTrackingService.AddSession(compositeKey, user.UserId);

            // 2. ALSO register plain SessionId for browser-level tracking (backward compatibility)
            //    This ensures different browsers are still detected
            _sessionTrackingService.AddSession(sessionId, user.UserId);

            // Update last login and store composite key in database
            user.LastLoginDate = DateTime.Now;
            user.LastSessionId = compositeKey; // Store the composite key
            _context.SaveChanges();
        }

        private async Task LogAuditAsync(int? userId, string action, bool success, string details = "")
        {
            // Sanitize details
            var sanitizedDetails = SanitizeForLogging(details);

            // Use generic identifier
            string genericIdentifier = userId.HasValue ? $"user_{userId}" : "anonymous";

            await _auditService.LogActivityAsync(
                userId,
                genericIdentifier,  
                action,
                success,
                sanitizedDetails,
                HttpContext);
        }

        private string SanitizeForLogging(string input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            // Remove dangerous characters
            return System.Text.RegularExpressions.Regex.Replace(input,
                @"[\r\n\t\\\/\|\`\$\{\}\[\]\(\)\*\&\^\%\#\@\!\~\=\+\<\>\?\:\;""']",
                " ")
                .Trim()
                .Substring(0, Math.Min(input.Length, 200));
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
        private string SanitizeEmailForLogging(string email)
        {
            if (string.IsNullOrEmpty(email))
                return "unknown";

            // Simple email sanitization for logging
            var parts = email.Split('@');
            if (parts.Length == 2)
            {
                var username = parts[0];
                var domain = parts[1];

                // Mask part of the username for privacy
                if (username.Length > 3)
                {
                    username = username.Substring(0, 3) + "***";
                }

                return $"{username}@{domain}";
            }

            // If not a valid email format, just sanitize it
            return System.Text.RegularExpressions.Regex.Replace(email,
                @"[^\w\.@-]", "?", System.Text.RegularExpressions.RegexOptions.None,
                TimeSpan.FromMilliseconds(500));
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

            // Remove any script tags and their content
            input = Regex.Replace(input, @"<script[^>]*>.*?</script>", string.Empty,
                RegexOptions.IgnoreCase | RegexOptions.Singleline);

            // Remove any iframe tags
            input = Regex.Replace(input, @"<iframe[^>]*>.*?</iframe>", string.Empty,
                RegexOptions.IgnoreCase | RegexOptions.Singleline);

            // Remove onclick, onerror, and other event handlers
            input = Regex.Replace(input, @"on\w+\s*=\s*[""'][^""']*[""']", string.Empty,
                RegexOptions.IgnoreCase);
            input = Regex.Replace(input, @"on\w+\s*=\s*[^\s>]*", string.Empty,
                RegexOptions.IgnoreCase);

            // Remove javascript: protocol
            input = Regex.Replace(input, @"javascript:", string.Empty,
                RegexOptions.IgnoreCase);

            // Remove data: protocol (can be used for XSS)
            input = Regex.Replace(input, @"data:", string.Empty,
                RegexOptions.IgnoreCase);

            // Remove vbscript: protocol
            input = Regex.Replace(input, @"vbscript:", string.Empty,
                RegexOptions.IgnoreCase);

            // HTML encode to convert special characters
            input = System.Net.WebUtility.HtmlEncode(input);

            return input;
        }

    } 
}   
    
