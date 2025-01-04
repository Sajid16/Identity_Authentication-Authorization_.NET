Authentication & Authorization using .NET with Identity & custom attribute
=============

### Features
- JWT Bearer token generation
- validation of bearer token
- custom validation attribute
- secure endpoint based on roles with [Authorize] decorator

#### nuget packages for JWT
- Microsoft.AspNetCore.Authentication.JwtBearer
- Microsoft.AspNetCore.Identity
- Microsoft.AspNetCore.Identity.EntityFrameworkCore

#### Highlighted discussions
- Authentication using [Authorize] decorator need authentication scheme. It can be custom or default scheme. Used the below code base inside program.cs or can be used with extention method.
```c#
//Adding Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})

// Adding Jwt Bearer
.AddJwtBearer(options =>
{
    options.SaveToken = true;
    options.RequireHttpsMetadata = false;
    options.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidAudience = builder.Configuration["JWT:ValidAudience"],
        ValidIssuer = builder.Configuration["JWT:ValidIssuer"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Secret"]))
    };
});
```
- Authentication using custom authentication attribute
>   prepared a custom authorization attribute & mentioned it at the action methods level to keep those methods validated before it comes to main methods. Here we can check the validation of JWT token as well as more validations if needed. Additionally we can pass parameters through attribute. For example: here we have secured the endpoints based on user role and those kinda checks has been done inside the custom attribute to make it available to certailn levels.
