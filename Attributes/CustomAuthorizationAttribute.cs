using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.IdentityModel.Tokens.Jwt;
using System.Net;

namespace IdentityAuthentication_Authorization.Attributes
{
    public class CustomAuthorizationAttribute : Attribute, IAsyncAuthorizationFilter
    {
        public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
        {
            var authorizationHandler = context.HttpContext.Request.Headers["Authorization"].FirstOrDefault();
            if (authorizationHandler is not null && authorizationHandler.StartsWith("Bearer ")) 
            {
                var token = authorizationHandler.Substring("Bearer ".Length).Trim();
                var handler = new JwtSecurityTokenHandler();
                if (handler.CanReadToken(token))
                {
                    var jwtToken = handler.ReadJwtToken(token);

                    if(jwtToken.ValidTo.AddHours(6) < DateTime.Now)
                    {
                        // token is expired
                        context.Result = new ObjectResult(new
                        {
                            IsSuccess = false,
                            Message = "Unauthorized. Token is expired."
                        })
                        {
                            StatusCode = (int)HttpStatusCode.Unauthorized
                        };
                    }
                }
                else
                {
                    // can't read token properly
                    context.Result = new ObjectResult(new
                    {
                        IsSuccess = false,
                        Message = "Unauthorized. Faulty Bearer Token."
                    })
                    {
                        StatusCode = (int)HttpStatusCode.Unauthorized
                    };
                }
            }
            else
            {
                // token is invalid
                context.Result = new ObjectResult(new {
                    IsSuccess = false,
                    Message = "Unauthorized"
                }) {
                    StatusCode = (int)HttpStatusCode.Unauthorized
                };
            }

            await Task.CompletedTask;
        }
    }
}
