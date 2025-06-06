using IdentityAuthentication_Authorization.Attributes;
using IdentityAuthentication_Authorization.Authentication;
using IdentityAuthentication_Authorization.Utilities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityAuthentication_Authorization.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    //[CustomAuthorization]
    public class AuthorizationsController : ControllerBase
    {
        [HttpGet]
        [Route("users")]
        [Authorize(Roles = UserRoles.User)]
        public async Task<IActionResult> GetUser()
        {
            return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = "User role is permitted to request." });
        }

        [HttpGet]
        [Route("admin")]
        [Authorize(Roles = UserRoles.Admin)]
        public async Task<IActionResult> GetAdmin()
        {
            return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = "Admin role is permitted to request." });
        }

        [HttpGet]
        [Route("multiple-roles")]
        [Authorize(Roles = $"{UserRoles.Admin}, {UserRoles.User}")]
        public async Task<IActionResult> GetMultiple()
        {
            return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = "Multiple roles are permitted to request." });
        }

        [HttpGet]
        [Route("multiple-roles-enum")]
        [Authorize(Roles = $"{nameof(ConstantValues.Roles.user)}, {nameof(ConstantValues.Roles.assistantmanager)}")]
        public async Task<IActionResult> GetMultipleEnum()
        {
            return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = "Multiple roles from enum are permitted to request." });
        }
    }
}
