using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FiTAX.Owin.Security.CustomHeaders
{
    public static class CustomHeadersAuthenticationExtensions
    {
        public static IAppBuilder UseCustomHeadersAuthentication(this IAppBuilder app, CustomHeadersAuthenticationOptions options)
        {
            return app.Use(typeof(CustomHeadersAuthenticationMiddleware), app, options);
        }
    }
}
