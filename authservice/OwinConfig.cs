using System;
using System.Configuration;
using System.Web.Http;

using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.FileSystems;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.OAuth;
using Microsoft.Owin.StaticFiles;
using System.Threading.Tasks;
using System.Security.Claims;

using Owin;

// Adapted from http://bitoftech.net/2014/06/01/token-based-authentication-asp-net-web-api-2-owin-asp-net-identity/
[assembly: OwinStartup(typeof(AuthService.OwinConfig))]

namespace AuthService
{
    public class OwinConfig
    {
        public static GoogleOAuth2AuthenticationOptions googleAuthOptions { get; private set; }

        public static OAuthBearerAuthenticationOptions OAuthBearerOptions { get; private set; }

        public void Configuration(IAppBuilder appBuilder)
        {
            appBuilder.Map(
                "/app",
                spa =>
                    {
                        spa.UseNancy();
                    });
            ConfigureOAuth(appBuilder);

            var config = new HttpConfiguration();
            config.Formatters.JsonFormatter.SerializerSettings.NullValueHandling =
                Newtonsoft.Json.NullValueHandling.Ignore;
            WebApiConfig.Register(config);

            var fileSystem = new PhysicalFileSystem("Webpage");
            var options = new FileServerOptions { FileSystem = fileSystem };

            appBuilder.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
            appBuilder.UseFileServer(options);
            appBuilder.UseWebApi(config);
        }

        public void ConfigureOAuth(IAppBuilder app)
        {
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);
            OAuthBearerOptions = new OAuthBearerAuthenticationOptions();
            OAuthAuthorizationServerOptions OAuthServerOptions =
                new OAuthAuthorizationServerOptions()
                {
                    AllowInsecureHttp = true,
                    TokenEndpointPath = new PathString("/token"),
                    AccessTokenExpireTimeSpan = TimeSpan.FromDays(1),
                    Provider = new DefaultAuthProvider()
                };

            // Token Generation
            app.UseOAuthAuthorizationServer(OAuthServerOptions);
            app.UseOAuthBearerAuthentication(OAuthBearerOptions);

            string GoogleClientId = "<yourclientid>";
            string GoogleClientSecret = "<yourclientsecret>";

            if (!string.IsNullOrEmpty(ConfigurationManager.AppSettings["GOOGLECLIENTID"]))
            {
                GoogleClientId = ConfigurationManager.AppSettings["GOOGLECLIENTID"];
            }

            if (!string.IsNullOrEmpty(ConfigurationManager.AppSettings["GOOGLECLIENTSECRET"]))
            {
                GoogleClientSecret = ConfigurationManager.AppSettings["GOOGLECLIENTSECRET"];
            }
            
            // Configure Google External Login
            googleAuthOptions = new GoogleOAuth2AuthenticationOptions()
            {
                ClientId = GoogleClientId,
                ClientSecret = GoogleClientSecret,
                Provider = new GoogleAuthProvider()
            };
            app.UseGoogleAuthentication(googleAuthOptions);
        }
    }
}