using Twilio;
using Twilio.Rest.Api.V2010.Account;
using Twilio.Types;

namespace FreshFarmMarket.Services
{
    public interface ISmsService
    {
        Task<bool> SendSmsAsync(string phoneNumber, string message);
        Task<bool> Send2FACodeAsync(string phoneNumber, string code);
    }

    public class SmsService : ISmsService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<SmsService> _logger;

        public SmsService(IConfiguration configuration, ILogger<SmsService> logger)
        {
            _configuration = configuration;
            _logger = logger;

            var twilioSettings = _configuration.GetSection("Twilio");
            TwilioClient.Init(
                twilioSettings["AccountSid"],
                twilioSettings["AuthToken"]
            );
        }

        public async Task<bool> SendSmsAsync(string phoneNumber, string message)
        {
            try
            {
                var twilioSettings = _configuration.GetSection("Twilio");

                if (!phoneNumber.StartsWith("+"))
                {
                    phoneNumber = "+65" + phoneNumber;
                }

                var messageResource = await MessageResource.CreateAsync(
                    to: new PhoneNumber(phoneNumber),
                    from: new PhoneNumber(twilioSettings["PhoneNumber"]),
                    body: message
                );

                return messageResource.Status != MessageResource.StatusEnum.Failed;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending SMS to {PhoneNumber}", phoneNumber);
                return false;
            }
        }

        public async Task<bool> Send2FACodeAsync(string phoneNumber, string code)
        {
            string message = $"Your Fresh Farm Market verification code is: {code}. This code will expire in 5 minutes.";
            return await SendSmsAsync(phoneNumber, message);
        }
    }
}