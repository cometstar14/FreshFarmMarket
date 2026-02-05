using FreshFarmMarket.Data;
using FreshFarmMarket.Models;
using Microsoft.EntityFrameworkCore;

namespace FreshFarmMarket.Services
{
    public interface IAuditService
    {
        Task LogActivityAsync(int? userId, string email, string action, bool success, string? details = null, HttpContext? httpContext = null);
        Task<List<AuditLog>> GetUserAuditLogsAsync(int userId, int count = 10);
    }

    public class AuditService : IAuditService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<AuditService> _logger;

        public AuditService(ApplicationDbContext context, ILogger<AuditService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task LogActivityAsync(int? userId, string emailOrIdentifier, string action, bool success, , string? details = null, HttpContext? httpContext = null)
        {
            try
            {
                // Sanitize ALL user inputs before storing in database
                
                var sanitizedDetails = SanitizeForDatabase(details);

                var auditLog = new AuditLog
                {
                    UserId = userId,
                    Email = emailOrIdentifier,  // Use sanitized version
                    Action = action,
                    Success = success,
                    Details = sanitizedDetails,  // Use sanitized version
                    Timestamp = DateTime.Now
                };

                if (httpContext != null)
                {
                    auditLog.IpAddress = httpContext.Connection.RemoteIpAddress?.ToString();
                    auditLog.UserAgent = SanitizeForDatabase(httpContext.Request.Headers["User-Agent"].ToString());
                }

                _context.AuditLogs.Add(auditLog);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                
                _logger.LogError(ex, "Error saving audit log");
            }
        }

        private string SanitizeForDatabase(string? input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            // Remove any dangerous characters for database storage
            return System.Text.RegularExpressions.Regex.Replace(input,
                @"[\r\n\t\\\/\|\`\$\{\}\[\]\(\)\*\&\^\%\#\@\!\~\=\+\<\>\?\:\;""']",
                " ")
                .Trim()
                .Substring(0, Math.Min(input.Length, 1000));
        }
        private string SanitizeLogInput(string? input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            // Remove newlines and carriage returns to prevent log injection
            return input
                .Replace("\r", "")
                .Replace("\n", "")
                .Replace("\t", " ")
                .Trim();
        }

        public async Task<List<AuditLog>> GetUserAuditLogsAsync(int userId, int count = 10)
        {
            return await _context.AuditLogs
                .Where(a => a.UserId == userId)
                .OrderByDescending(a => a.Timestamp)
                .Take(count)
                .ToListAsync();
        }
    }
}