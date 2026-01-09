using System.Text.Json;
using System.Text.Json.Serialization;

namespace FreshFarmMarket.Services
{
    public interface IReCaptchaService
    {
        Task<bool> ValidateTokenAsync(string token);
    }

    public class ReCaptchaService : IReCaptchaService
    {
        private readonly IConfiguration _configuration;
        private readonly HttpClient _httpClient;
        private readonly ILogger<ReCaptchaService> _logger;

        public ReCaptchaService(IConfiguration configuration, IHttpClientFactory httpClientFactory, ILogger<ReCaptchaService> logger)
        {
            _configuration = configuration;
            _httpClient = httpClientFactory.CreateClient();
            _logger = logger;
        }

        public async Task<bool> ValidateTokenAsync(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                _logger.LogWarning("reCAPTCHA token is null or empty");
                return false;
            }

            try
            {
                var secretKey = _configuration["ReCaptcha:SecretKey"];
                var url = $"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={token}";

                var response = await _httpClient.PostAsync(url, null);
                var jsonString = await response.Content.ReadAsStringAsync();

                _logger.LogInformation($"reCAPTCHA Response: {jsonString}");

                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                };

                var result = JsonSerializer.Deserialize<ReCaptchaResponse>(jsonString, options);

                if (result == null)
                {
                    _logger.LogWarning("Failed to deserialize reCAPTCHA response");
                    return false;
                }

                _logger.LogInformation($"reCAPTCHA Success: {result.Success}, Score: {result.Score}");

                return result.Success && result.Score >= 0.5;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating reCAPTCHA token");
                return false;
            }
        }

        private class ReCaptchaResponse
        {
            [JsonPropertyName("success")]
            public bool Success { get; set; }

            [JsonPropertyName("score")]
            public double Score { get; set; }

            [JsonPropertyName("action")]
            public string Action { get; set; } = string.Empty;

            [JsonPropertyName("challenge_ts")]
            public string ChallengeTs { get; set; } = string.Empty;

            [JsonPropertyName("hostname")]
            public string Hostname { get; set; } = string.Empty;

            [JsonPropertyName("error-codes")]
            public string[]? ErrorCodes { get; set; }
        }
    }
}