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
                // Log to console
                _logger.LogInformation($"📱 SMS to {phoneNumber}: {message}");

                // Show in console for easy viewing
                Console.WriteLine($"\n═══════════════════════════════════════════");
                Console.WriteLine($"📱 MOCK SMS SENT");
                Console.WriteLine($"To: {phoneNumber}");
                Console.WriteLine($"Message: {message}");
                Console.WriteLine($"═══════════════════════════════════════════\n");

                // Log to file
                await LogToFile(phoneNumber, message);

                return true; // Always return success
            }
            catch (Exception ex)
            {
                var sanitizedPhone = SanitizePhoneNumber(phoneNumber);
                _logger.LogError(ex, "Error sending SMS to {PhoneNumber}", sanitizedPhone);
                return false;
            } 
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