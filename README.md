# Fresh Farm Market - Application Security Project
**IT2163-04 - Nanyang Polytechnic**

## 🎓 Academic Project
This is a course assignment for IT2163 Application Security, demonstrating secure web application development using ASP.NET Core MVC.

## 🔒 Security Features Implemented

### Authentication & Authorization
- ✅ Secure user registration with email uniqueness validation
- ✅ Strong password policy (12+ chars, uppercase, lowercase, numbers, special characters)
- ✅ Password hashing using PBKDF2 with salt
- ✅ Account lockout after 3 failed login attempts
- ✅ Automatic account recovery after lockout period
- ✅ Session management with timeout
- ✅ Multiple login detection across devices
- ✅ Two-Factor Authentication (2FA) via SMS and Email

### Data Protection
- ✅ AES-256 encryption for sensitive data (credit card numbers)
- ✅ Secure password storage with salted hashing
- ✅ Password history enforcement (prevents reuse of last 2 passwords)
- ✅ Password age policies (minimum and maximum)

### Input Validation & Anti-Attack Measures
- ✅ Client-side and server-side input validation
- ✅ SQL Injection prevention using Entity Framework parameterized queries
- ✅ XSS (Cross-Site Scripting) protection via HTML encoding
- ✅ CSRF (Cross-Site Request Forgery) protection using anti-forgery tokens
- ✅ Google reCAPTCHA v3 integration for bot prevention
- ✅ File upload restrictions (type and size validation)

### Session & Error Management
- ✅ Secure session configuration (HttpOnly, Secure, SameSite cookies)
- ✅ Session timeout with automatic redirect
- ✅ Custom error pages (404, 403, 500)
- ✅ Comprehensive audit logging of user activities

### Advanced Features
- ✅ Email-based password reset functionality
- ✅ SMS-based 2FA code delivery
- ✅ Password strength indicator with real-time feedback
- ✅ Account lockout with configurable duration
- ✅ Audit trail for security events

## 🛠️ Technologies Used
- **Framework**: ASP.NET Core 8.0 MVC
- **Database**: SQL Server LocalDB with Entity Framework Core
- **Authentication**: Custom implementation with PBKDF2 hashing
- **Encryption**: AES-256 for data at rest
- **Anti-Bot**: Google reCAPTCHA v3
- **Email**: MailKit with Gmail SMTP
- **SMS**: Twilio API
- **Frontend**: Bootstrap 5, jQuery, jQuery Validation

## 📋 Prerequisites
- .NET 8.0 SDK
- Visual Studio 2022 or VS Code
- SQL Server LocalDB (comes with Visual Studio)
- Git

## ⚙️ Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/FreshFarmMarket.git
cd FreshFarmMarket
```

### 2. Configure Application Settings
Update `appsettings.json` with your credentials:

#### Required Configurations:

**A. Google reCAPTCHA v3**
1. Visit: https://www.google.com/recaptcha/admin
2. Register your site for reCAPTCHA v3
3. Get your Site Key and Secret Key
4. Update in `appsettings.json`:
```json
"ReCaptcha": {
  "SiteKey": "your-site-key-here",
  "SecretKey": "your-secret-key-here"
}
```

**B. Email Service (Gmail)**
1. Enable 2-Factor Authentication on your Gmail account
2. Generate an App Password: https://myaccount.google.com/apppasswords
3. Update in `appsettings.json`:
```json
"Email": {
  "SmtpServer": "smtp.gmail.com",
  "SmtpPort": 587,
  "SenderEmail": "your-email@gmail.com",
  "SenderName": "Fresh Farm Market",
  "Username": "your-email@gmail.com",
  "Password": "your-16-char-app-password"
}
```

**C. Twilio SMS (for 2FA)**
1. Sign up at: https://www.twilio.com
2. Get a phone number and credentials
3. Update in `appsettings.json`:
```json
"Twilio": {
  "AccountSid": "your-account-sid",
  "AuthToken": "your-auth-token",
  "PhoneNumber": "+1234567890"
}
```

**D. Encryption Keys**
Generate secure random keys:
```json
"Encryption": {
  "Key": "your-32-character-encryption-key",
  "IV": "your-16-char-iv"
}
```

### 3. Database Setup
```bash
# Restore NuGet packages
dotnet restore

# Apply database migrations
dotnet ef database update

# Or if using Visual Studio Package Manager Console:
Update-Database
```

### 4. Run the Application
```bash
# Using .NET CLI
dotnet run

# Or press F5 in Visual Studio
```

The application will be available at:
- HTTPS: https://localhost:7085
- HTTP: http://localhost:5179

## 📁 Project Structure
```
FreshFarmMarket/
├── Controllers/
│   ├── AccountController.cs    # Registration, Login, Logout
│   ├── HomeController.cs        # Homepage
│   └── ErrorController.cs       # Error handling
├── Models/
│   ├── User.cs                  # User entity
│   ├── AuditLog.cs             # Audit logging
│   ├── PasswordHistory.cs      # Password history
│   ├── LoginViewModel.cs       # Login form model
│   └── RegisterViewModel.cs    # Registration form model
├── Services/
│   ├── EncryptionService.cs    # AES encryption & password hashing
│   ├── EmailService.cs         # Email functionality
│   ├── SmsService.cs           # SMS/2FA functionality
│   ├── AuditService.cs         # Activity logging
│   ├── ReCaptchaService.cs     # reCAPTCHA validation
│   └── SessionTrackingService.cs # Multi-login detection
├── Data/
│   └── ApplicationDbContext.cs # EF Core context
├── Filters/
│   └── SessionTimeoutAttribute.cs # Session management
├── Views/
│   ├── Account/
│   │   ├── Login.cshtml
│   │   └── Register.cshtml
│   ├── Home/
│   │   └── Index.cshtml
│   └── Shared/
│       ├── _Layout.cshtml
│       └── Error.cshtml
└── wwwroot/
    └── uploads/                # User photo uploads
```

## 🔐 Security Checklist
All items from the assignment security checklist have been implemented:
- [x] Registration with duplicate email check
- [x] Strong password requirements (12+ chars, complexity)
- [x] Client-side and server-side password validation
- [x] Password strength indicator
- [x] Data encryption (credit card)
- [x] Password hashing with salt
- [x] File upload restrictions
- [x] Secure session management
- [x] Session timeout with redirect
- [x] Multiple login detection
- [x] Login with rate limiting
- [x] Account lockout (3 attempts)
- [x] Proper logout with session clearing
- [x] Audit logging
- [x] Google reCAPTCHA v3
- [x] SQL Injection prevention
- [x] CSRF protection
- [x] XSS protection
- [x] Input validation (client & server)
- [x] Proper error handling
- [x] Custom error pages (404, 403, 500)
- [x] Source code analysis (GitHub)
- [x] Automatic account recovery
- [x] Password history (max 2)
- [x] Change password functionality
- [x] Reset password (email/SMS)
- [x] Min/max password age
- [x] Two-Factor Authentication

## 🧪 Testing
1. Register a new user with all required fields
2. Test password strength indicator
3. Try duplicate email registration
4. Test login with wrong password (trigger lockout)
5. Test session timeout
6. Test multiple logins from different browsers
7. View encrypted credit card on homepage
8. Test 2FA functionality

## 📊 Database Schema
- **Users**: User account information
- **PasswordHistories**: Password change history
- **AuditLogs**: Security event logging

## ⚠️ Important Notes
- This is an academic project for learning purposes
- Never commit sensitive credentials to version control
- Use User Secrets or environment variables in production
- Database uses LocalDB (development only)

## 📝 Assignment Details
- **Module**: IT2163-04 Application Security
- **Institution**: Nanyang Polytechnic
- **Assessment**: Practical Assignment (ICA 35%)
- **Components**: 
  - Implementation (85%)
  - Documentation (15%)

## 👤 Author
**[Parnika]**  
Admin No: [243294W]  
IT2163-04 - Nanyang Polytechnic

## 📄 License
This project is for educational purposes only.

---
**Note**: All security configurations need to be properly set up before running the application. See Setup Instructions above.