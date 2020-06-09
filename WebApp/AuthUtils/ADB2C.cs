using System;
using System.Collections.Generic;
using System.Configuration;
using System.Runtime.Caching;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Identity.Client;

namespace WebApp.AuthUtils.ADB2C
{
    public static class Globals
    {
        // App config settings
        public static string ClientId = ConfigurationManager.AppSettings["ida:ClientId"];
        public static string ClientSecret = ConfigurationManager.AppSettings["ida:ClientSecret"];
        public static string AadInstance = ConfigurationManager.AppSettings["ida:AadInstance"];
        public static string Tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        public static string TenantId = ConfigurationManager.AppSettings["ida:TenantId"];
        public static string RedirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];
        public static string ServiceUrl = ConfigurationManager.AppSettings["api:TaskServiceUrl"];

        // B2C policy identifiers
        public static string SignUpSignInPolicyId = ConfigurationManager.AppSettings["ida:SignUpSignInPolicyId"];
        public static string EditProfilePolicyId = ConfigurationManager.AppSettings["ida:EditProfilePolicyId"];
        public static string ResetPasswordPolicyId = ConfigurationManager.AppSettings["ida:ResetPasswordPolicyId"];

        public static string DefaultPolicy = SignUpSignInPolicyId;

        // API Scopes
        public static string ApiIdentifier = ConfigurationManager.AppSettings["api:ApiIdentifier"];
        public static string ReadTasksScope = ApiIdentifier + ConfigurationManager.AppSettings["api:ReadScope"];
        public static string WriteTasksScope = ApiIdentifier + ConfigurationManager.AppSettings["api:WriteScope"];
        public static string[] Scopes = new string[] { ReadTasksScope, WriteTasksScope };

        // OWIN auth middleware constants
        public const string ObjectIdElement = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";

        // Authorities
        public static string B2CAuthority = string.Format(AadInstance, Tenant, DefaultPolicy);
        public static string WellKnownMetadata = $"{AadInstance}/v2.0/.well-known/openid-configuration";

    }

    /// <summary>
    /// claim keys constants
    /// </summary>
    public static class ClaimConstants
    {
        public const string ObjectId = "http://schemas.microsoft.com/identity/claims/objectidentifier";
        public const string TenantId = "http://schemas.microsoft.com/identity/claims/tenantid";
        public const string tid = "tid";
    }

    public static class ClaimsPrincipalExtension
    {
        /// <summary>
        /// Get the B2C Account identifier for an MSAL.NET account from a ClaimsPrincipal
        /// </summary>
        /// <param name="claimsPrincipal">Claims principal</param>
        /// <returns>A string corresponding to an account identifier as defined in <see cref="Microsoft.Identity.Client.AccountId.Identifier"/></returns>
        public static string GetB2CMsalAccountId(this ClaimsPrincipal claimsPrincipal)
        {
            string userObjectId = GetObjectId(claimsPrincipal);
            string tenantId = Globals.TenantId;

            if (!string.IsNullOrWhiteSpace(userObjectId) && !string.IsNullOrWhiteSpace(tenantId))
            {
                return $"{userObjectId}.{tenantId}";
            }

            return null;
        }

        /// <summary>
        /// Get the unique object ID associated with the claimsPrincipal
        /// </summary>
        /// <param name="claimsPrincipal">Claims principal from which to retrieve the unique object id</param>
        /// <returns>Unique object ID of the identity, or <c>null</c> if it cannot be found</returns>
        public static string GetObjectId(this ClaimsPrincipal claimsPrincipal)
        {
            var objIdclaim = claimsPrincipal.FindFirst(ClaimTypes.NameIdentifier);

            if (objIdclaim == null)
            {
                objIdclaim = claimsPrincipal.FindFirst("sub");
            }

            return objIdclaim != null ? objIdclaim.Value : string.Empty;
        }

        /// <summary>
        /// Builds a ClaimsPrincipal from an IAccount
        /// </summary>
        /// <param name="account">The IAccount instance.</param>
        /// <returns>A ClaimsPrincipal built from IAccount</returns>
        public static ClaimsPrincipal ToClaimsPrincipal(this IAccount account)
        {
            if (account != null)
            {
                var identity = new ClaimsIdentity();
                identity.AddClaim(new Claim(ClaimConstants.ObjectId, account.HomeAccountId.ObjectId));
                identity.AddClaim(new Claim(ClaimConstants.TenantId, account.HomeAccountId.TenantId));
                identity.AddClaim(new Claim(ClaimTypes.Upn, account.Username));
                return new ClaimsPrincipal(identity);
            }

            return null;
        }

        public static class MsalAppBuilder
        {
            /// <summary>
            /// Shared method to create an IConfidentialClientApplication from configuration and attach the application's token cache implementation
            /// </summary>
            /// <returns></returns>
            public static IConfidentialClientApplication BuildConfidentialClientApplication()
            {
                return BuildConfidentialClientApplication(ClaimsPrincipal.Current);
            }

            /// <summary>
            /// Shared method to create an IConfidentialClientApplication from configuration and attach the application's token cache implementation
            /// </summary>
            /// <param name="currentUser">The current ClaimsPrincipal</param>
            public static IConfidentialClientApplication BuildConfidentialClientApplication(ClaimsPrincipal currentUser)
            {
                IConfidentialClientApplication clientapp = ConfidentialClientApplicationBuilder.Create(Globals.ClientId)
                      .WithClientSecret(Globals.ClientSecret)
                      .WithRedirectUri(Globals.RedirectUri)
                      .WithB2CAuthority(Globals.B2CAuthority)
                      .Build();

                MSALPerUserMemoryTokenCache userTokenCache = new MSALPerUserMemoryTokenCache(clientapp.UserTokenCache, currentUser ?? ClaimsPrincipal.Current);
                return clientapp;
            }

            /// <summary>
            /// Common method to remove the cached tokens for the currently signed in user
            /// </summary>
            /// <returns></returns>
            public static async Task ClearUserTokenCache()
            {
                IConfidentialClientApplication clientapp = ConfidentialClientApplicationBuilder.Create(Globals.ClientId)
                    .WithB2CAuthority(Globals.B2CAuthority)
                    .WithClientSecret(Globals.ClientSecret)
                    .WithRedirectUri(Globals.RedirectUri)
                    .Build();

                // We only clear the user's tokens.
                MSALPerUserMemoryTokenCache userTokenCache = new MSALPerUserMemoryTokenCache(clientapp.UserTokenCache);
                var userAccounts = await clientapp.GetAccountsAsync();

                foreach (var account in userAccounts)
                {
                    //Remove the users from the MSAL's internal cache
                    await clientapp.RemoveAsync(account);
                }
                userTokenCache.Clear();

            }
        }

        public class MSALPerUserMemoryTokenCache
        {
            /// <summary>
            /// The backing MemoryCache instance
            /// </summary>
            internal readonly MemoryCache memoryCache = MemoryCache.Default;

            /// <summary>
            /// The duration till the tokens are kept in memory cache. In production, a higher value, upto 90 days is recommended.
            /// </summary>
            private readonly DateTimeOffset cacheDuration = DateTimeOffset.Now.AddHours(48);

            /// <summary>
            /// Once the user signes in, this will not be null and can be ontained via a call to Thread.CurrentPrincipal
            /// </summary>
            internal ClaimsPrincipal SignedInUser;

            /// <summary>
            /// Initializes a new instance of the <see cref="MSALPerUserMemoryTokenCache"/> class.
            /// </summary>
            /// <param name="tokenCache">The client's instance of the token cache.</param>
            public MSALPerUserMemoryTokenCache(ITokenCache tokenCache)
            {
                this.Initialize(tokenCache, ClaimsPrincipal.Current);
            }

            /// <summary>
            /// Initializes a new instance of the <see cref="MSALPerUserMemoryTokenCache"/> class.
            /// </summary>
            /// <param name="tokenCache">The client's instance of the token cache.</param>
            /// <param name="user">The signed-in user for whom the cache needs to be established.</param>
            public MSALPerUserMemoryTokenCache(ITokenCache tokenCache, ClaimsPrincipal user)
            {
                this.Initialize(tokenCache, user);
            }

            /// <summary>Initializes the cache instance</summary>
            /// <param name="tokenCache">The ITokenCache passed through the constructor</param>
            /// <param name="user">The signed-in user for whom the cache needs to be established..</param>
            private void Initialize(ITokenCache tokenCache, ClaimsPrincipal user)
            {
                this.SignedInUser = user;

                tokenCache.SetBeforeAccess(this.UserTokenCacheBeforeAccessNotification);
                tokenCache.SetAfterAccess(this.UserTokenCacheAfterAccessNotification);
                tokenCache.SetBeforeWrite(this.UserTokenCacheBeforeWriteNotification);

                if (this.SignedInUser == null)
                {
                    // No users signed in yet, so we return
                    return;
                }
            }

            /// <summary>
            /// Explores the Claims of a signed-in user (if available) to populate the unique Id of this cache's instance.
            /// </summary>
            /// <returns>The signed in user's object.tenant Id , if available in the ClaimsPrincipal.Current instance</returns>
            internal string GetMsalAccountId()
            {
                if (this.SignedInUser != null)
                {
                    return this.SignedInUser.GetB2CMsalAccountId();
                }
                return null;
            }

            /// <summary>
            /// Loads the user token cache from memory.
            /// </summary>
            private void LoadUserTokenCacheFromMemory(ITokenCacheSerializer tokenCache)
            {
                string cacheKey = this.GetMsalAccountId();

                if (string.IsNullOrWhiteSpace(cacheKey))
                    return;

                // Ideally, methods that load and persist should be thread safe. MemoryCache.Get() is thread safe.
                byte[] tokenCacheBytes = (byte[])this.memoryCache.Get(this.GetMsalAccountId());
                tokenCache.DeserializeMsalV3(tokenCacheBytes);
            }

            /// <summary>
            /// Persists the user token blob to the memoryCache.
            /// </summary>
            private void PersistUserTokenCache(ITokenCacheSerializer tokenCache)
            {
                string cacheKey = this.GetMsalAccountId();

                if (string.IsNullOrWhiteSpace(cacheKey))
                    return;

                // Ideally, methods that load and persist should be thread safe.MemoryCache.Get() is thread safe.
                this.memoryCache.Set(this.GetMsalAccountId(), tokenCache.SerializeMsalV3(), this.cacheDuration);
            }

            /// <summary>
            /// Clears the TokenCache's copy of this user's cache.
            /// </summary>
            public void Clear()
            {
                this.memoryCache.Remove(this.GetMsalAccountId());
            }

            /// <summary>
            /// Triggered right after MSAL accessed the cache.
            /// </summary>
            /// <param name="args">Contains parameters used by the MSAL call accessing the cache.</param>
            private void UserTokenCacheAfterAccessNotification(TokenCacheNotificationArgs args)
            {
                this.SetSignedInUserFromNotificationArgs(args);

                // if the access operation resulted in a cache update
                if (args.HasStateChanged)
                {
                    this.PersistUserTokenCache(args.TokenCache);
                }
            }

            /// <summary>
            /// Triggered right before MSAL needs to access the cache. Reload the cache from the persistence store in case it changed since the last access.
            /// </summary>
            /// <param name="args">Contains parameters used by the MSAL call accessing the cache.</param>
            private void UserTokenCacheBeforeAccessNotification(TokenCacheNotificationArgs args)
            {
                this.LoadUserTokenCacheFromMemory(args.TokenCache);
            }

            /// <summary>
            /// if you want to ensure that no concurrent write take place, use this notification to place a lock on the entry
            /// </summary>
            /// <param name="args">Contains parameters used by the MSAL call accessing the cache.</param>
            private void UserTokenCacheBeforeWriteNotification(TokenCacheNotificationArgs args)
            {
                // Since we are using a MemoryCache ,whose methods are threads safe, we need not to do anything in this handler.
            }

            /// <summary>
            /// To keep the cache, ClaimsPrincipal and Sql in sync, we ensure that the user's object Id we obtained by MSAL after
            /// successful sign-in is set as the key for the cache.
            /// </summary>
            /// <param name="args">Contains parameters used by the MSAL call accessing the cache.</param>
            private void SetSignedInUserFromNotificationArgs(TokenCacheNotificationArgs args)
            {
                if (this.SignedInUser == null && args.Account != null)
                {
                    this.SignedInUser = args.Account.ToClaimsPrincipal();
                }
            }
        }
    }
}