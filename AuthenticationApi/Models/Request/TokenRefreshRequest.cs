using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace AuthenticationApi.Models.Request;

public class TokenRefreshRequest
{
    [Required]
    [JsonPropertyName("refresh-token")]
    public string? RefreshToken { get; set; }
}
