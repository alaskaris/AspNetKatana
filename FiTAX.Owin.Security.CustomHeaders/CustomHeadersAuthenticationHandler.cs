using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace FiTAX.Owin.Security.CustomHeaders
{
    class CustomHeadersAuthenticationHandler : AuthenticationHandler<CustomHeadersAuthenticationOptions>
    {
        protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            string userId = Request.Headers.ContainsKey(Options.ClaimNameKey) ? Request.Headers.GetValues(Options.ClaimNameKey)?.First() : null;
            if (userId != null)
            {
                // ASP.Net Identity requires the NameIdentitifer field to be set or it won't  
                // accept the external login (AuthenticationManagerExtensions.GetExternalLoginInfo)
                var identity = new ClaimsIdentity(Options.AuthenticationType);
                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userId, null, Options.AuthenticationType));
                identity.AddClaim(new Claim(ClaimTypes.Name, userId, null, Options.AuthenticationType));

                var properties = new AuthenticationProperties(); //Options.StateDataFormat.Unprotect(Request.Query["state"]);

                return Task.FromResult(new AuthenticationTicket(identity, properties));
            }

            return Task.FromResult<AuthenticationTicket>(null);
        }   

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
                return Task.FromResult(0);

            return base.ApplyResponseChallengeAsync();
        }

        public override Task<bool> InvokeAsync()
        {
            return base.InvokeAsync();
        }
    }
}
