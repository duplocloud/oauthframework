using AuthService;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Http;

namespace Duplo.OAuth
{
    [RoutePrefix("api/Account")]
    public class AccountController : ApiController
    {
        public AccountController()
        {
        }

        private IAuthenticationManager Authentication
        {
            get { return Request.GetOwinContext().Authentication; }
        }

        // GET api/Account/ExternalLogin
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalCookie)]
        [AllowAnonymous]
        [Route("ExternalLogin", Name = "ExternalLogin")]
        public IHttpActionResult GetExternalLogin(string provider, string error = null)
        {
            string redirectUri = string.Empty;

            if (error != null)
            {
                return BadRequest(Uri.EscapeDataString(error));
            }

            if ((User == null) || !User.Identity.IsAuthenticated)
            {
                return new ChallengeResult(provider, this);
            }

            var redirectUriValidationResult = ValidateClientAndRedirectUri(this.Request, ref redirectUri);

            if (!string.IsNullOrWhiteSpace(redirectUriValidationResult))
            {
                return BadRequest(redirectUriValidationResult);
            }

            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            if (externalLogin == null)
            {
                return InternalServerError();
            }

            if (externalLogin.LoginProvider != provider)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                return new ChallengeResult(provider, this);
            }

            //IdentityUser user = await _repo.FindAsync(new UserLoginInfo(externalLogin.LoginProvider, externalLogin.ProviderKey));
            var accessTokenResponse = GenerateLocalAccessTokenResponse(externalLogin.Email);
            //bool hasRegistered = true;

            redirectUri = string.Format("{0}#external_access_token={1}&provider={2}&accessToken={3}&external_user_name={4}&external_email={5}",
                                            redirectUri,
                                            externalLogin.ExternalAccessToken,
                                            externalLogin.LoginProvider,
                                            accessTokenResponse.GetValue("access_token"),
                                            externalLogin.UserName,
                                            externalLogin.Email);

            return Redirect(redirectUri);
        }

        // POST api/Account/LogOut
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalCookie)]
        [AllowAnonymous]
        [Route("LogOut", Name = "LogOut")]
        public void LogOut()
        {
            Log.Logger.Writeline("This is a logout call");
            try
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                var token = this.Request.Headers.GetValues("Authorization");
                Log.Logger.Writeline($"Test: Header: {token}");
            }
            catch (Exception ex)
            {
                Log.Logger.Writeline("Exception in signout API {0}", ex);
                throw ThrowResponseException(this.Request, System.Net.HttpStatusCode.BadRequest, ex.Message);
            }
        }

        public static HttpResponseException ThrowResponseException(HttpRequestMessage request, HttpStatusCode statusCode, string message, string errorResourceCode = null)
        {
            return new HttpResponseException(
             new HttpResponseMessage(statusCode)
             {
                 Content = new StringContent(message)
             });
        }

        private async Task<ParsedExternalAccessToken> VerifyExternalAccessToken(string provider, string accessToken)
        {
            ParsedExternalAccessToken parsedToken = null;

            var verifyTokenEndPoint = "";
            HttpResponseMessage response = null;
            if (provider == "Google")
            {
                verifyTokenEndPoint = string.Format("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={0}", accessToken);
                var client = new HttpClient();
                var uri = new Uri(verifyTokenEndPoint);
                response = await client.GetAsync(uri);
            }
            else
            {
                return null;
            }

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();

                dynamic jObj = (JObject)Newtonsoft.Json.JsonConvert.DeserializeObject(content);

                parsedToken = new ParsedExternalAccessToken();

                if (provider == "Google")
                {
                    parsedToken.user_id = jObj["user_id"];
                    parsedToken.app_id = jObj["audience"];

                    if (!string.Equals(OwinConfig.googleAuthOptions.ClientId, parsedToken.app_id, StringComparison.OrdinalIgnoreCase))
                    {
                        return null;
                    }
                }
            }

            return parsedToken;
        }

        public static JObject GenerateLocalAccessTokenResponse(string userName)
        {
            var tokenExpiration = TimeSpan.FromDays(1);

            ClaimsIdentity identity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);

            identity.AddClaim(new Claim("Email", userName));
            //identity.AddClaim(new Claim(AuthorizationCore.CLAIM_IDENTITY_TYPE, userName));
            identity.AddClaim(new Claim("role", "user"));

            var props = new AuthenticationProperties()
            {
                IssuedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.Add(tokenExpiration),
            };

            var ticket = new AuthenticationTicket(identity, props);

            var accessToken = OwinConfig.OAuthBearerOptions.AccessTokenFormat.Protect(ticket);

            JObject tokenResponse = new JObject(
                                        new JProperty("userName", userName),
                                        new JProperty("access_token", accessToken),
                                        new JProperty("token_type", "bearer"),
                                        new JProperty("expires_in", tokenExpiration.TotalSeconds.ToString()),
                                        new JProperty(".issued", ticket.Properties.IssuedUtc.ToString()),
                                        new JProperty(".expires", ticket.Properties.ExpiresUtc.ToString())
                                        );

            return tokenResponse;
        }

        private string ValidateClientAndRedirectUri(HttpRequestMessage request, ref string redirectUriOutput)
        {
            Uri redirectUri;

            var redirectUriString = GetQueryString(Request, "redirect_uri");

            if (string.IsNullOrWhiteSpace(redirectUriString))
            {
                return "redirect_uri is required";
            }

            bool validUri = Uri.TryCreate(redirectUriString, UriKind.Absolute, out redirectUri);

            if (!validUri)
            {
                return "redirect_uri is invalid";
            }

            var clientId = GetQueryString(Request, "client_id");

            if (string.IsNullOrWhiteSpace(clientId))
            {
                return "client_Id is required";
            }

            redirectUriOutput = redirectUri.AbsoluteUri;

            return string.Empty;
        }

        private string GetQueryString(HttpRequestMessage request, string key)
        {
            var queryStrings = request.GetQueryNameValuePairs();

            if (queryStrings == null)
            {
                return null;
            }

            var match = queryStrings.FirstOrDefault(keyValue => string.Compare(keyValue.Key, key, true) == 0);

            if (string.IsNullOrEmpty(match.Value))
            {
                return null;
            }

            return match.Value;
        }

        [AllowAnonymous]
        [HttpGet]
        [Route("ObtainLocalAccessToken")]
        public async Task<IHttpActionResult> ObtainLocalAccessToken(string provider, string externalAccessToken)
        {
            if (string.IsNullOrWhiteSpace(provider) || string.IsNullOrWhiteSpace(externalAccessToken))
            {
                return BadRequest("Provider or external access token is not sent");
            }

            var verifiedAccessToken = await VerifyExternalAccessToken(provider, externalAccessToken);
            if (verifiedAccessToken == null)
            {
                return BadRequest("Invalid Provider or External Access Token");
            }

            // IdentityUser user = await _repo.FindAsync(new UserLoginInfo(provider, verifiedAccessToken.user_id));
            // TODO: validate we have this user in the DB
            bool hasRegistered = true;

            if (!hasRegistered)
            {
                return BadRequest("External user is not registered");
            }

            //generate access token response
            var accessTokenResponse = GenerateLocalAccessTokenResponse(verifiedAccessToken.user_id);

            return Ok(accessTokenResponse);
        }

        [AllowAnonymous]
        [HttpGet]
        [Route("MicrosoftClientId", Name = "MicrosoftClientId")]
        public string GetMicrosoftClientId()
        {
            return ConfigurationManager.AppSettings["MICROSOFTCLIENTID"];
        }

        [AllowAnonymous]
        [HttpGet]
        [Route("MicrosoftLogin", Name = "MicrosoftLogin")]
        public async Task<IHttpActionResult> GetMicrosoftAuthorizedAccessToken()
        {
            var ClientId = string.Empty;
            var ClientSecret = string.Empty;
            var endPoint = "https://login.microsoftonline.com";
            if (!string.IsNullOrEmpty(ConfigurationManager.AppSettings["MICROSOFTCLIENTID"]))
            {
                ClientId = ConfigurationManager.AppSettings["MICROSOFTCLIENTID"];
            }

            if (!string.IsNullOrEmpty(ConfigurationManager.AppSettings["MICROSOFTCLIENTSECRET"]))
            {
                ClientSecret = ConfigurationManager.AppSettings["MICROSOFTCLIENTSECRET"];
            }

            if (string.IsNullOrEmpty(ClientId)
                || string.IsNullOrEmpty(ClientSecret))
            {
                throw new InvalidDataException("No Microsoft Client ID or Client password has been set. Contact your administrator or use a different identity provider");
            }

            string redirectUri = GetQueryString(Request, "redirect_uri");
            // string lCurrentUrl = this.Request.RequestUri.ToString();

            string code = GetQueryString(Request, "code");

            if (string.IsNullOrEmpty(code))
            {
                string lOauthEp = endPoint + "/common/oauth2/v2.0/authorize?scope=openid+profile+email&response_type=code&client_id=" + ClientId + "&redirect_uri=" + redirectUri;
                return Redirect(lOauthEp);
            }

            var graph_URL = "https://graph.microsoft.com/v1.0";

            // If we have the code then call WP to validate and find user
            var lRequest = new Dictionary<string, string> { { "client_id", ClientId }, { "client_secret", ClientSecret }, { "code", code }, { "redirect_uri", redirectUri }, { "grant_type", "authorization_code" } };
            string lMSAccessToken = await ValidateMicrosoftToken(endPoint + "/common/oauth2/v2.0/token", lRequest);

            // Now get the user information with this token
            string lMSMeEp = graph_URL + "/me";

            HttpClient client = new HttpClient();
            var graph_endpoint = "https://graph.microsoft.com/v1.0/me";
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", lMSAccessToken);
            var lResponse = await client.GetAsync(graph_endpoint);
            var lData = await (lResponse.Content.ReadAsStringAsync());
            MicrosoftUserInfo lInfo = JsonConvert.DeserializeObject<MicrosoftUserInfo>(lData);
            string lUser = lInfo.userPrincipalName;

            var accessTokenResponse = GenerateLocalAccessTokenResponse(lUser);
            accessTokenResponse.Add(new JProperty("name", lInfo.displayName));

            return Ok(accessTokenResponse);
        }

        private async Task<string> ValidateMicrosoftToken(string aInUrl, Dictionary<string, string> lRequest)
        {
            HttpClient client = new HttpClient();
            var encodedContent = new FormUrlEncodedContent(lRequest);
            var response = await client.PostAsync(aInUrl, encodedContent).ConfigureAwait(false);
            var responseString = await (response.Content.ReadAsStringAsync());
            return JsonConvert.DeserializeObject<MicrosoftTokenResponse>(responseString).access_token;
        }

        private class MicrosoftTokenResponse
        {
            public string access_token { get; set; }
        }

        private class MicrosoftUserInfo
        {
            public string userPrincipalName { get; set; }
            public string displayName { get; set; }
        }

        private class MicrosoftTokenRequest
        {
            public string grant_type { get; set; }
            public string code { get; set; }
            public string client_id { get; set; }
            public string client_secret { get; set; }
            public string redirect_uri { get; set; }

            public MicrosoftTokenRequest()
            {
                grant_type = "authorization_code";
            }
        }

        public class ExternalLoginData
        {
            public string LoginProvider { get; set; }
            public string ProviderKey { get; set; }
            public string UserName { get; set; }
            public string ExternalAccessToken { get; set; }
            public string Email { get; set; }

            public static ExternalLoginData FromIdentity(ClaimsIdentity identity)
            {
                if (identity == null)
                {
                    return null;
                }

                Claim providerKeyClaim = identity.FindFirst(ClaimTypes.NameIdentifier);

                if (providerKeyClaim == null || String.IsNullOrEmpty(providerKeyClaim.Issuer) || String.IsNullOrEmpty(providerKeyClaim.Value))
                {
                    return null;
                }

                if (providerKeyClaim.Issuer == ClaimsIdentity.DefaultIssuer)
                {
                    return null;
                }

                return new ExternalLoginData
                {
                    LoginProvider = providerKeyClaim.Issuer,
                    ProviderKey = providerKeyClaim.Value,
                    UserName = identity.FindFirstValue(ClaimTypes.Name),
                    ExternalAccessToken = identity.FindFirstValue("ExternalAccessToken"),
                    Email = identity.FindFirstValue("Email")
                };
            }
        }
    }
}