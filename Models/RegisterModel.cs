using IdentityAuthentication_Authorization.Authentication;
using IdentityAuthentication_Authorization.Utilities;
using System.ComponentModel.DataAnnotations;
using System.Data;

namespace IdentityAuthentication_Authorization.Models
{
    public class RegisterModel
    {
        [Required(ErrorMessage = "User Name is required")]
        public string Username { get; set; }

        [EmailAddress]
        [Required(ErrorMessage = "Email is required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }

    }

    public class GenericRegisterModel
    {
        [Required(ErrorMessage = "User Name is required")]
        public string Username { get; set; }

        [EmailAddress]
        [Required(ErrorMessage = "Email is required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }

        [Required(ErrorMessage = "Role name is required")]
        public ConstantValues.Roles Role { get; set; }

    }
}
