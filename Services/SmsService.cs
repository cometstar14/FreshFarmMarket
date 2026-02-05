using Microsoft.Extensions.Logging;
using System.IO;

namespace FreshFarmMarket.Services
{
    public interface ISmsService
    {
        Task<bool> SendSmsAsync(string phoneNumber, string message);
        Task<bool> Send2FACodeAsync(string phoneNumber, string code);
    }

    public class SmsService : ISmsService
    {
        private readonly ILogger<SmsService> _logger;
        private readonly IWebHostEnvironment _env;

        public SmsService(ILogger<SmsService> logger, IWebHostEnvironment env)
        {
            _logger = logger;
            _env = env;

            // Remove Twilio initialization - we don't need it
            Console.WriteLine("📱 Mock SMS Service initialized - Running in development mode");
        }

        public async Task<bool> SendSmsAsync(string phoneNumber, string message)
        {
            try
            {
                // ✅ FIX 1: Use structured logging
                var sanitizedPhone = SanitizePhoneNumber(phoneNumber);
                var sanitizedMessage = SanitizeLogInput(message);

                _logger.LogInformation("SMS sent to {PhoneNumber}: {Message}",
                    sanitizedPhone, sanitizedMessage);

                // Show in console for easy viewing
                Console.WriteLine($"\n═══════════════════════════════════════════");
                Console.WriteLine($"📱 MOCK SMS SENT");
                Console.WriteLine($"To: {sanitizedPhone}");  // Use sanitized
                Console.WriteLine($"Message: {sanitizedMessage.Substring(0, Math.Min(sanitizedMessage.Length, 50))}...");  // Truncate
                Console.WriteLine($"═══════════════════════════════════════════\n");

                // Log to file with sanitized data
                await LogToFile(sanitizedPhone, sanitizedMessage);

                return true;
            }
            catch (Exception ex)
            {
                var sanitizedPhone = SanitizePhoneNumber(phoneNumber);
                _logger.LogError(ex, "Error sending SMS to {PhoneNumber}", sanitizedPhone);
                return false;
            }
        }

        private string SanitizeLogInput(string? input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            // Step 1: Remove newlines, tabs, and carriage returns
            var sanitized = input
                .Replace("\r", "[CR]")
                .Replace("\n", "[LF]")
                .Replace("\t", "[TAB]")
                .Replace("\0", "[NULL]");

            // Step 2: Remove control characters (ASCII 0-31, except tab/newline which we already handled)
            sanitized = System.Text.RegularExpressions.Regex.Replace(sanitized,
                @"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", string.Empty);

            // Step 3: Remove any log injection patterns
            // Prevent multiline log entries that could break log format
            sanitized = System.Text.RegularExpressions.Regex.Replace(sanitized,
                @"(\|\||\&\&|;|\||\`|\$|{|}|\[|\]|\(|\)|\*|\&|\^|%|#|@|!|~|=|\+|<|>|?|:|;|""|'|\\|/)",
                " ");

            // Step 4: Truncate to prevent log flooding attacks
            const int MAX_LOG_LENGTH = 500;
            if (sanitized.Length > MAX_LOG_LENGTH)
            {
                sanitized = sanitized.Substring(0, MAX_LOG_LENGTH) + "...[TRUNCATED]";
            }

            // Step 5: Remove any remaining dangerous sequences
            sanitized = System.Text.RegularExpressions.Regex.Replace(sanitized,
                @"(javascript:|data:|vbscript:|on\w+\s*=)",
                "[REMOVED]",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            // Step 6: Trim and return
            return sanitized.Trim();
        }

        private string SanitizePhoneNumber(string phoneNumber)
        {
            if (string.IsNullOrEmpty(phoneNumber))
                return "unknown";

            // Mask middle digits for privacy and remove injection characters
            var cleaned = phoneNumber.Replace("\r", "").Replace("\n", "").Trim();
            if (cleaned.Length > 6)
            {
                return cleaned.Substring(0, 3) + "****" + cleaned.Substring(cleaned.Length - 3);
            }
            return "****";
        }
        

        public async Task<bool> Send2FACodeAsync(string phoneNumber, string code)
        {
            string message = $"Your Fresh Farm Market verification code is: {code}. This code will expire in 5 minutes.";
            return await SendSmsAsync(phoneNumber, message);
        }

        private async Task LogToFile(string phoneNumber, string message)
        {
            try
            {
                var logDirectory = Path.Combine(Directory.GetCurrentDirectory(), "Logs");
                if (!Directory.Exists(logDirectory))
                {
                    Directory.CreateDirectory(logDirectory);
                }

                // Log to sms_log.txt
                var logFile = Path.Combine(logDirectory, "sms_log.txt");
                var logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] To: {phoneNumber}\nMessage: {message}\n{new string('-', 50)}\n";
                await File.AppendAllTextAsync(logFile, logEntry);

                // Also create a file with just the latest code for easy access
                var latestCodeFile = Path.Combine(logDirectory, "latest_verification_code.txt");
                await File.WriteAllTextAsync(latestCodeFile,
                    $"Verification Code: {GetCodeFromMessage(message)}\n" +
                    $"Phone: {phoneNumber}\n" +
                    $"Time: {DateTime.Now:HH:mm:ss}\n" +
                    $"Use this code: {GetCodeFromMessage(message)}");

                _logger.LogInformation($"✅ Verification code saved to: {latestCodeFile}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to write SMS log to file");
            }
        }

        private string GetCodeFromMessage(string message)
        {
            // Extract the 6-digit code from the message
            var match = System.Text.RegularExpressions.Regex.Match(message, @"\b\d{6}\b");
            return match.Success ? match.Value : "CODE_NOT_FOUND";
        }
    }
}