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

        public async Task LogActivityAsync(int? userId, string email, string action, bool success, string? details = null, HttpContext? httpContext = null)
        {
            try
            {
                // Sanitize email and details to prevent log injection
                var sanitizedEmail = SanitizeLogInput(email);
                var sanitizedDetails = SanitizeLogInput(details);

                var auditLog = new AuditLog
                {
                    UserId = userId,
                    Email = email,
                    Action = action,
                    Success = success,
                    Details = details,
                    Timestamp = DateTime.Now
                };

                if (httpContext != null)
                {
                    auditLog.IpAddress = httpContext.Connection.RemoteIpAddress?.ToString();
                    auditLog.UserAgent = SanitizeLogInput(httpContext.Request.Headers["User-Agent"].ToString());
                }

                _context.AuditLogs.Add(auditLog);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging audit activity for user {Email}", email);
            }
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