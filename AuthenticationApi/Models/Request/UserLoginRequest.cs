using System.ComponentModel.DataAnnotations;

namespace AuthenticationApi.Models.Request;

public class UserLoginRequest
{
    [Required(ErrorMessage = "The {0} is required")]
    [EmailAddress(ErrorMessage = "The {0} is in a incorrect format")]
    public string? Email { get; set; }

    [Required(ErrorMessage = "The {0} is required")]
    [StringLength(100, ErrorMessage = "The {0} must have between {2} and {1} characters", MinimumLength = 6)]
    public string? Password { get; set; }
}
