using Microsoft.Owin;
using Microsoft.Owin.Security.Infrastructure;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FiTAX.Owin.Security.CustomHeaders
{
    public class CustomHeadersAuthenticationMiddleware : AuthenticationMiddleware<CustomHeadersAuthenticationOptions>
    {
        public CustomHeadersAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, CustomHeadersAuthenticationOptions options)
            : base(next, options)
        {

        }
        protected override AuthenticationHandler<CustomHeadersAuthenticationOptions> CreateHandler()
        {
            return new CustomHeadersAuthenticationHandler();
        }
    }
}
