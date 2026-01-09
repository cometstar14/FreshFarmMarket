using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using FreshFarmMarket.Data;
using FreshFarmMarket.Services;

namespace FreshFarmMarket.Controllers
{
    public class HomeController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IEncryptionService _encryptionService;

        public HomeController(ApplicationDbContext context, IEncryptionService encryptionService)
        {
            _context = context;
            _encryptionService = encryptionService;
        }

        public async Task<IActionResult> Index()
        {
            var userId = HttpContext.Session.GetInt32("UserId");
            if (!userId.HasValue)
            {
                return RedirectToAction("Login", "Account");
            }

            var user = await _context.Users.FindAsync(userId.Value);
            if (user == null)
            {
                HttpContext.Session.Clear();
                return RedirectToAction("Login", "Account");
            }

            ViewBag.DecryptedCreditCard = _encryptionService.Decrypt(user.CreditCardNo);
            ViewBag.MaskedCreditCard = MaskCreditCard(ViewBag.DecryptedCreditCard);

            return View(user);
        }

        private string MaskCreditCard(string creditCard)
        {
            if (string.IsNullOrEmpty(creditCard) || creditCard.Length < 4)
                return "****";

            return "****-****-****-" + creditCard.Substring(creditCard.Length - 4);
        }

        public IActionResult Error()
        {
            return View();
        }
    }
}