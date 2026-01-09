using Microsoft.AspNetCore.Mvc;

namespace FreshFarmMarket.Controllers
{
    public class ErrorController : Controller
    {
        [Route("Error/{statusCode}")]
        public IActionResult HttpStatusCodeHandler(int statusCode)
        {
            ViewBag.StatusCode = statusCode;

            switch (statusCode)
            {
                case 404:
                    ViewBag.ErrorMessage = "Sorry, the page you're looking for could not be found.";
                    ViewBag.ErrorTitle = "Page Not Found";
                    break;
                case 403:
                    ViewBag.ErrorMessage = "Access Denied. You don't have permission to access this resource.";
                    ViewBag.ErrorTitle = "Access Forbidden";
                    break;
                case 500:
                    ViewBag.ErrorMessage = "An internal server error occurred. Please try again later.";
                    ViewBag.ErrorTitle = "Internal Server Error";
                    break;
                default:
                    ViewBag.ErrorMessage = "An error occurred while processing your request.";
                    ViewBag.ErrorTitle = "Error";
                    break;
            }

            return View("Error");
        }

        [Route("Home/Error")]
        public IActionResult Error()
        {
            ViewBag.ErrorTitle = "Error";
            ViewBag.ErrorMessage = "An unexpected error occurred. Please try again.";
            return View();
        }
    }
}