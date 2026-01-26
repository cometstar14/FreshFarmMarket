using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace FreshFarmMarket.Services
{
    public interface IEmailService
    {
        Task<bool> SendEmailAsync(string toEmail, string subject, string htmlMessage);
        Task<bool> SendPasswordResetEmailAsync(string toEmail, string resetLink);
        Task<bool> Send2FACodeAsync(string toEmail, string code);
    }

    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public async Task<bool> SendEmailAsync(string toEmail, string subject, string htmlMessage)
        {
            try
            {
                var emailSettings = _configuration.GetSection("Email");
                var message = new MimeMessage();
                message.From.Add(new MailboxAddress(
                    emailSettings["SenderName"],
                    emailSettings["SenderEmail"]
                ));
                message.To.Add(new MailboxAddress("", toEmail));
                message.Subject = subject;

                var bodyBuilder = new BodyBuilder
                {
                    HtmlBody = htmlMessage
                };
                message.Body = bodyBuilder.ToMessageBody();

                using (var client = new SmtpClient())
                {
                    await client.ConnectAsync(
                        emailSettings["SmtpServer"],
                        int.Parse(emailSettings["SmtpPort"] ?? "587"),
                        SecureSocketOptions.StartTls
                    );

                    await client.AuthenticateAsync(
                        emailSettings["Username"],
                        emailSettings["Password"]
                    );

                    await client.SendAsync(message);
                    await client.DisconnectAsync(true);
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending email to {Email}", toEmail);
                return false;
            }
        }

        public async Task<bool> SendPasswordResetEmailAsync(string toEmail, string resetLink)
        {
            string subject = "Password Reset Request - Fresh Farm Market";
            string htmlMessage = $@"
                <html>
                <body style='font-family: Arial, sans-serif;'>
                    <h2>Password Reset Request</h2>
                    <p>You have requested to reset your password for Fresh Farm Market.</p>
                    <p>Click the link below to reset your password:</p>
                    <p><a href='{resetLink}' style='background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;'>Reset Password</a></p>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you did not request this password reset, please ignore this email.</p>
                    <br/>
                    <p>Best regards,<br/>Fresh Farm Market Team</p>
                </body>
                </html>";

            return await SendEmailAsync(toEmail, subject, htmlMessage);
        }
        public async Task<bool> Send2FACodeAsync(string toEmail, string code)
        {
            string subject = "Your Fresh Farm Market Verification Code";
            string htmlMessage = $@"
        <html>
        <body style='font-family: Arial, sans-serif;'>
            <div style='max-width: 600px; margin: 0 auto; padding: 20px;'>
                <h2 style='color: #4CAF50;'>Two-Factor Authentication</h2>
                <p>Your verification code is:</p>
                <div style='background-color: #4CAF50; color: white; padding: 20px; text-align: center; margin: 20px 0; border-radius: 5px;'>
                    <h1 style='margin: 0; letter-spacing: 10px; font-size: 36px;'>{code}</h1>
                </div>
                <p>This code will expire in 5 minutes.</p>
                <p>If you did not request this code, please ignore this email.</p>
                <br/>
                <p>Best regards,<br/>Fresh Farm Market Team</p>
            </div>
        </body>
        </html>";

            return await SendEmailAsync(toEmail, subject, htmlMessage);
        }
    }
}