using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FiTAX.Owin.Security.CustomHeaders
{
    public class CustomHeadersAuthenticationOptions : AuthenticationOptions
    {
        public CustomHeadersAuthenticationOptions(bool isActive = false, 
            string claimNameKey = "X-UserName",
            string claimRolesKey = "X-UserRoles",
            bool isPersisted = false ): base(Constants.DefaultAuthenticationType)
        {
            IsActive = isActive;
            ClaimNameKey = claimNameKey;
            ClaimRolesKey = claimRolesKey;
            IsPersisted = isPersisted;
            
        }

        public bool IsActive { get; set; }
        public string ClaimNameKey { get; set; }
        public string ClaimRolesKey { get; set; }
        public bool IsPersisted { get; set; }
    }
}
