﻿using IdentityAuthentication_Authorization.Attributes;
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
        [Authorize(Roles = $"{nameof(ConstantValues.Roles.User)}, {nameof(ConstantValues.Roles.AssistantManager)}")]
        public async Task<IActionResult> GetMultipleEnum()
        {
            return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = "Multiple roles from enum are permitted to request." });
        }

        [HttpGet]
        [Route("admin&manageronlypolicy")]
        [Authorize(Policy = "AdminAndManagerOnly")]
        public async Task<IActionResult> adminandmanageronlypolicy()
        {
            return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = "adminandmanageronlypolicy are permitted to request." });
        }

        [HttpGet]
        [Route("user&assistantmanageronlypolicy")]  
        [Authorize(Policy = "UserAndAssistantManagerOnly")]
        public async Task<IActionResult> userandassistantmanageronlypolicy()
        {
            return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = "userandassistantmanageronlypolicy are permitted to request." });
        }
    }
}
