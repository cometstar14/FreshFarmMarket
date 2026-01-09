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
                (actionName == "Login" || actionName == "Register"))
            {
                return;
            }

            // Check if user has a session
            var userId = session.GetInt32("UserId");

            if (userId.HasValue)
            {
                // Check session last activity
                var lastActivityStr = session.GetString("LastActivity");

                if (!string.IsNullOrEmpty(lastActivityStr))
                {
                    var lastActivity = DateTime.Parse(lastActivityStr);
                    var timeoutMinutes = 15; // Must match Program.cs

                    if (DateTime.UtcNow > lastActivity.AddMinutes(timeoutMinutes))
                    {
                        // Session expired
                        var sessionId = session.GetString("SessionId");
                        if (!string.IsNullOrEmpty(sessionId))
                        {
                            var sessionTracking = httpContext.RequestServices
                                .GetService<ISessionTrackingService>();
                            sessionTracking?.RemoveSession(sessionId);
                        }

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