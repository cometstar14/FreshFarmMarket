using FreshFarmMarket.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace FreshFarmMarket.Filters
{
    public class SessionTimeoutAttribute : ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext context)
        {
            var httpContext = context.HttpContext;
            var session = httpContext.Session;

            // Skip session check for login/register pages and static files
            var controllerName = context.Controller?.GetType().Name ?? "";
            var actionName = context.RouteData.Values["action"]?.ToString() ?? "";

            // Allow access to Account actions without session
            if (controllerName.Contains("Account") &&
                (actionName == "Login" ||
                 actionName == "Register" ||
                 actionName == "VerifyOtp" ||
                 actionName == "ResendOtp" ||
                 actionName == "ForgotPassword" ||
                 actionName == "ResetPassword" ||
                 actionName == "IsEmailAvailable"))
            {
                return;
            }

            // Check if user has a session
            var userId = session.GetInt32("UserId");

            if (userId.HasValue)
            {
                // ============================================================
                // CRITICAL: Multiple Login Detection
                // Strategy: Use composite key (SessionId_TabId) if TabId exists,
                // otherwise fall back to just SessionId for backward compatibility
                // ============================================================
                var currentSessionId = session.GetString("SessionId");
                var currentTabId = session.GetString("TabId"); // Get from session, not header

                var sessionTracking = httpContext.RequestServices.GetService<ISessionTrackingService>();

                if (!string.IsNullOrEmpty(currentSessionId) && sessionTracking != null)
                {
                    string keyToCheck;

                    // If we have a TabId stored in session, use composite key
                    // Otherwise, use just SessionId (for browsers without JS)
                    if (!string.IsNullOrEmpty(currentTabId))
                    {
                        keyToCheck = $"{currentSessionId}_{currentTabId}";
                    }
                    else
                    {
                        keyToCheck = currentSessionId;
                    }

                    // Check if this session/tab combination is still valid
                    var isSessionActive = sessionTracking.IsSessionActive(keyToCheck, userId.Value);

                    if (!isSessionActive)
                    {
                        // This session/tab was terminated by another login
                        session.Clear();

                        // Redirect to login with multiple login message
                        context.Result = new RedirectToActionResult("Login", "Account", new
                        {
                            multiple = "true"
                        });
                        return;
                    }
                }
                // ============================================================
                // END OF MULTIPLE LOGIN DETECTION
                // ============================================================

                // Check session last activity for timeout
                var lastActivityStr = session.GetString("LastActivity");

                if (!string.IsNullOrEmpty(lastActivityStr))
                {
                    var lastActivity = DateTime.Parse(lastActivityStr);
                    var timeoutMinutes = 15; // Must match Program.cs

                    if (DateTime.UtcNow > lastActivity.AddMinutes(timeoutMinutes))
                    {
                        // Session expired due to inactivity
                        if (!string.IsNullOrEmpty(currentSessionId) && sessionTracking != null)
                        {
                            // Remove both possible keys (with and without TabId)
                            if (!string.IsNullOrEmpty(currentTabId))
                            {
                                sessionTracking.RemoveSession($"{currentSessionId}_{currentTabId}");
                            }
                            sessionTracking.RemoveSession(currentSessionId);
                        }

                        // Clear session
                        session.Clear();

                        // Store attempted URL for redirect after login
                        var returnUrl = httpContext.Request.Path + httpContext.Request.QueryString;
                        if (!string.IsNullOrEmpty(returnUrl) && returnUrl != "/")
                        {
                            session.SetString("ReturnUrl", returnUrl);
                        }

                        // Redirect to login with timeout message
                        context.Result = new RedirectToActionResult("Login", "Account", new
                        {
                            timeout = "true"
                        });
                        return;
                    }
                }

                // Update last activity time (sliding expiration)
                session.SetString("LastActivity", DateTime.UtcNow.ToString("o"));
            }
            else
            {
                // No session but trying to access protected page
                // Allow access to Home/Index and public pages
                if (!(controllerName.Contains("Home") && actionName == "Index") &&
                    !(controllerName.Contains("Error")))
                {
                    // Store attempted URL
                    var returnUrl = httpContext.Request.Path + httpContext.Request.QueryString;
                    if (!string.IsNullOrEmpty(returnUrl) && returnUrl != "/")
                    {
                        session.SetString("ReturnUrl", returnUrl);
                    }

                    // Redirect to login
                    context.Result = new RedirectToActionResult("Login", "Account", null);
                    return;
                }
            }
        }
    }
}