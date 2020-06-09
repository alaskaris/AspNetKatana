using System;
using System.Configuration;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web.Http;
using FiTAX.Owin.Security.CustomHeaders;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security.WsFederation;
using Owin;

namespace WebApp
{
    public partial class Startup
    {
        public void ConfigurationAuth(IAppBuilder app)
        {
            string STSRealm = ConfigurationManager.AppSettings["STSWtrealm"];
            var use_sts = Convert.ToBoolean(ConfigurationManager.AppSettings["UseSTSAuthentication"] ?? bool.FalseString);

            #region Cookie

            double defaultCookieAuthenticationTimeoutDuration = 60;
            bool defaultCookieAuthenticationSlidingExpiration = true;
            var cookieTimeoutDuration = Convert.ToDouble(ConfigurationManager.AppSettings["CookieAuthenticationTimeoutDuration"] ?? defaultCookieAuthenticationTimeoutDuration.ToString());
            var cookieSlidingExpiration = Convert.ToBoolean(ConfigurationManager.AppSettings["CookieAuthenticationSlidingExpiration"] ?? defaultCookieAuthenticationSlidingExpiration.ToString());
            var cookieSingleDomain = ConfigurationManager.AppSettings["CookieAuthenticationSingleDomain"] ?? String.Empty;
            var cookieDomainName = ConfigurationManager.AppSettings["CookieAuthenticationDomainName"] ?? String.Empty;
            var cookieName = (!String.IsNullOrEmpty(cookieSingleDomain) ? cookieSingleDomain : (use_sts) ? STSRealm : "fitaxcookie");
            var cookieSameSite = Convert.ToBoolean(ConfigurationManager.AppSettings["AddCookiesSameSite"] ?? "false");
            var cookieSameSiteMode = ConfigurationManager.AppSettings["CookiesSameSite"] ?? "None";

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            var cookieAuthenticationOptions = new CookieAuthenticationOptions
            {
                CookieName = cookieName,
                CookieHttpOnly = true,
                ExpireTimeSpan = TimeSpan.FromMinutes(cookieTimeoutDuration),
                SlidingExpiration = cookieSlidingExpiration,
                Provider = new CookieAuthenticationProvider
                {
                    OnResponseSignIn = context =>
                    {
                        context.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(cookieTimeoutDuration);
                        context.Properties.AllowRefresh = cookieSlidingExpiration;
                    }
                }
            };
            if (!String.IsNullOrEmpty(cookieDomainName.Trim())) cookieAuthenticationOptions.CookieDomain = cookieDomainName.Trim();
            if (cookieSameSite)
            {
                switch (cookieSameSiteMode)
                {
                    case "None":
                        cookieAuthenticationOptions.CookieSameSite = Microsoft.Owin.SameSiteMode.None;
                        break;
                    case "Lax":
                        cookieAuthenticationOptions.CookieSameSite = Microsoft.Owin.SameSiteMode.Lax;
                        break;
                    case "Strict":
                        cookieAuthenticationOptions.CookieSameSite = Microsoft.Owin.SameSiteMode.Strict;
                        break;
                    default: break;

                }
            }

            #endregion

            /*
             * Uncomment the following to keep compatibility with the older FITAX versions for SingleDomain 
             */
            //cookieAuthenticationOptions.AuthenticationType = WsFederationAuthenticationDefaults.AuthenticationType;

            app.UseCookieAuthentication(cookieAuthenticationOptions);

            #region Redirect

            var useRedirection = Convert.ToBoolean(ConfigurationManager.AppSettings["Redirection:Use"] ?? bool.FalseString);
            string redirectUri = ConfigurationManager.AppSettings["Redirection:URL"];

            app.Use((context, continuation) =>
            {
                bool shouldRedirect = true;
                foreach (var cookie in context.Request.Cookies)
                {
                    if (cookie.Key == cookieName)
                    {
                        shouldRedirect = false;
                    }
                }

                if (useRedirection && shouldRedirect)
                {
                    context.Response.StatusCode = 302;
                    context.Response.Headers.Remove("Location");
                    context.Response.Headers.Add("Location", new string[] { redirectUri });
                    return Task.Delay(0);
                }
                else
                {
                    return continuation();
                }
            });

            #endregion

            #region WsFederation

            string STSMetadata = ConfigurationManager.AppSettings["STSADFSMetadata"];

            /* 
             * Unsafe way to disable server certificate validation 
             */
            //ServicePointManager.ServerCertificateValidationCallback = (sender, certifacete, chain, ssPolicyErros) => true;

            Microsoft.IdentityModel.Protocols.IConfigurationRetriever<Microsoft.IdentityModel.Protocols.WsFederation.WsFederationConfiguration> configurationRetriever = new Microsoft.IdentityModel.Protocols.WsFederation.WsFederationConfigurationRetriever();
            /* If the ConfigurationManager is set, the BackchannelHttpHandler and BackchannelCertificateValidator are never used even when set!
             * Normally, they are used to initialize the HttpClient that is user by the IDocumentRetriever. The HttpClient is based on the WebRequestHandler.
             * If a BackchannelHttpHandler is defined/passed in the Options, it must be cast-able to WebRequestHanlder. An error will be raised otherwise.
             * If a BackchannelCertificateValidator is defined/passed in the Options, the WebRequestHandler's ServerCertificateValidationCallback is set to its 
             * Validate method (see an example below).
             * 
             * To sum up:
             * - If ConfigurationManager is passed, then the BackchannelHttpHandler & BackchannelCertificateValidator are not used. The validator must be set through the HttpClient of the HttpDocumentRetriever
             * - If ConfigurationManager is null, the BackchannelHttpHandler & BackchannelCertificateValidator are used if both set, as long as BackchannelHttpHandler can be cast to WebRequestHandler
             * - If ConfigurationManager is null and BackchannelHttpHandler is null, BackchannelCertificateValidator.Validate method is used as the BackchannelHttpHandler's ServerCertificateValidationCallback
             */
            System.Net.Http.WebRequestHandler webRequestHandler = new System.Net.Http.WebRequestHandler() { ServerCertificateValidationCallback = (object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) => true };
            Microsoft.IdentityModel.Protocols.IDocumentRetriever documentRetriever = new Microsoft.IdentityModel.Protocols.HttpDocumentRetriever(new System.Net.Http.HttpClient(webRequestHandler)) { RequireHttps = false };
            Microsoft.IdentityModel.Protocols.ConfigurationManager<Microsoft.IdentityModel.Protocols.WsFederation.WsFederationConfiguration> configurationManager = new Microsoft.IdentityModel.Protocols.ConfigurationManager<Microsoft.IdentityModel.Protocols.WsFederation.WsFederationConfiguration>(STSMetadata, configurationRetriever, documentRetriever);
            Microsoft.Owin.Security.ICertificateValidator certificateValidator = new IgnoringCertificateValidator();
            WsFederationAuthenticationOptions wsFederationAuthenticationOptions = new WsFederationAuthenticationOptions()
            {
                ConfigurationManager = configurationManager,
                MetadataAddress = STSMetadata,
                Wtrealm = STSRealm,
                SignInAsAuthenticationType = WsFederationAuthenticationDefaults.AuthenticationType,
                TokenValidationParameters = new TokenValidationParameters
                {
                    ValidAudience = STSRealm,
                }
            };

            #endregion

            //app.UseWsFederationAuthentication(wsFederationAuthenticationOptions);

            #region Custom Headers

            var authType = CookieAuthenticationDefaults.AuthenticationType;
            var customHeadersIsActive = Convert.ToBoolean(ConfigurationManager.AppSettings["CustomHttpHeader:Use"] ?? "false");
            var customHeadersIsPersisted = Convert.ToBoolean(ConfigurationManager.AppSettings["CustomHttpHeader:PersistWithCookie"] ?? "false");
            CustomHeadersAuthenticationOptions customHeadersAuthenticationOptions = new CustomHeadersAuthenticationOptions()
            {
                IsActive = customHeadersIsActive,
                ClaimRolesKey = ConfigurationManager.AppSettings["CustomHttpHeader:Roles"],
                ClaimNameKey = ConfigurationManager.AppSettings["CustomHttpHeader:Name"],
                IsPersisted = customHeadersIsPersisted
            };

            #endregion

            //app.UseCustomHeadersAuthentication(customHeadersAuthenticationOptions);

            #region SAML

            #endregion

            #region OAuth/Azure

            // Required for Azure webapps, as by default they force TLS 1.2 and this project attempts 1.0
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            var openIdConnectAuthenticationOptions = new OpenIdConnectAuthenticationOptions()
            {
                // Generate the metadata address using the tenant and policy information
                MetadataAddress = String.Format(AuthUtils.ADB2C.Globals.WellKnownMetadata, AuthUtils.ADB2C.Globals.Tenant, AuthUtils.ADB2C.Globals.DefaultPolicy),

                // These are standard OpenID Connect parameters, with values pulled from web.config
                ClientId = AuthUtils.ADB2C.Globals.ClientId,
                RedirectUri = AuthUtils.ADB2C.Globals.RedirectUri,
                PostLogoutRedirectUri = AuthUtils.ADB2C.Globals.RedirectUri,

                // Specify the callbacks for each type of notifications
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    RedirectToIdentityProvider = OnRedirectToIdentityProvider,
                    AuthorizationCodeReceived = OnAuthorizationCodeReceived,
                    AuthenticationFailed = OnAuthenticationFailed,
                },

                // Specify the claim type that specifies the Name property.
                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    ValidateIssuer = false
                },

                // Specify the scope by appending all of the scopes requested into one string (separated by a blank space)
                Scope = $"openid profile offline_access {AuthUtils.ADB2C.Globals.ReadTasksScope} {AuthUtils.ADB2C.Globals.WriteTasksScope}"
            };

            #endregion

            app.UseOpenIdConnectAuthentication(openIdConnectAuthenticationOptions);

        }

        #region OAuth/Azure Helper Methods

        /*
         *  On each call to Azure AD B2C, check if a policy (e.g. the profile edit or password reset policy) has been specified in the OWIN context.
         *  If so, use that policy when making the call. Also, don't request a code (since it won't be needed).
         */
        private Task OnRedirectToIdentityProvider(RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            var policy = notification.OwinContext.Get<string>("Policy");

            if (!string.IsNullOrEmpty(policy) && !policy.Equals(AuthUtils.ADB2C.Globals.DefaultPolicy))
            {
                notification.ProtocolMessage.Scope = OpenIdConnectScope.OpenId;
                notification.ProtocolMessage.ResponseType = OpenIdConnectResponseType.IdToken;
                notification.ProtocolMessage.IssuerAddress = notification.ProtocolMessage.IssuerAddress.ToLower().Replace(AuthUtils.ADB2C.Globals.DefaultPolicy.ToLower(), policy.ToLower());
            }

            return Task.FromResult(0);
        }

        /*
         * Catch any failures received by the authentication middleware and handle appropriately
         */
        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            notification.HandleResponse();

            // Handle the error code that Azure AD B2C throws when trying to reset a password from the login page
            // because password reset is not supported by a "sign-up or sign-in policy"
            if (notification.ProtocolMessage.ErrorDescription != null && notification.ProtocolMessage.ErrorDescription.Contains("AADB2C90118"))
            {
                // If the user clicked the reset password link, redirect to the reset password route
                notification.Response.Redirect("/Account/ResetPassword");
            }
            else if (notification.Exception.Message == "access_denied")
            {
                notification.Response.Redirect("/");
            }
            else
            {
                notification.Response.Redirect("/Home/Error?message=" + notification.Exception.Message);
            }

            return Task.FromResult(0);
        }

        /*
         * Callback function when an authorization code is received
         */
        private async Task OnAuthorizationCodeReceived(AuthorizationCodeReceivedNotification notification)
        {
            try
            {
                /*
				 The `MSALPerUserMemoryTokenCache` is created and hooked in the `UserTokenCache` used by `IConfidentialClientApplication`.
				 At this point, if you inspect `ClaimsPrinciple.Current` you will notice that the Identity is still unauthenticated and it has no claims,
				 but `MSALPerUserMemoryTokenCache` needs the claims to work properly. Because of this sync problem, we are using the constructor that
				 receives `ClaimsPrincipal` as argument and we are getting the claims from the object `AuthorizationCodeReceivedNotification context`.
				 This object contains the property `AuthenticationTicket.Identity`, which is a `ClaimsIdentity`, created from the token received from
				 Azure AD and has a full set of claims.
				 */
                IConfidentialClientApplication confidentialClient = AuthUtils.ADB2C.ClaimsPrincipalExtension.MsalAppBuilder.BuildConfidentialClientApplication(new ClaimsPrincipal(notification.AuthenticationTicket.Identity));

                // Upon successful sign in, get & cache a token using MSAL
                AuthenticationResult result = await confidentialClient.AcquireTokenByAuthorizationCode(AuthUtils.ADB2C.Globals.Scopes, notification.Code).ExecuteAsync();
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.BadRequest,
                    ReasonPhrase = $"Unable to get authorization code {ex.Message}."
                });
            }
        }

        #endregion
    }

    public class IgnoringCertificateValidator : ICertificateValidator
    {
        public bool Validate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
    }
}
