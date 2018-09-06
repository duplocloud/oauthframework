using Newtonsoft.Json.Linq;
using System.Net.Http;
using System.Web.Http;

namespace AuthService
{
    public class ProxyController : ApiController
    {
        private static string ServerAddress
        {
            get { return AuthService.GetInstance().EngineAddress; }
        }

        static ProxyController()
        {
        }

        [Authorize]
        [HttpGet]
        public JToken GetProxyWithParam(string subscriptionId, string api, string val)
        {
            return GetProxy(subscriptionId, api);
        }

        [Authorize]
        [HttpGet]
        public JToken GetProxy(string subscriptionId, string api)
        {
            Log.Logger.Writeline("Get API called {0}", this.Request.RequestUri);

            string lBackendUrl = GetBackendUrl();
            return ProxyUtils.GetProxy(lBackendUrl);
        }

        [Authorize]
        [HttpPost]
        public JToken PostProxyWithParam(string subscriptionId, string api, string val)
        {
            return PostProxy(subscriptionId, api);
        }

        [Authorize]
        [HttpPost]
        public JToken PostProxy(string subscriptionId, string api)
        {
            HttpRequestMessage lRequest = this.Request;
            Log.Logger.Writeline("POST API called {0} ", lRequest.RequestUri);

            string lBackendUrl = GetBackendUrl();

            return ProxyUtils.PostProxy(lRequest, lBackendUrl);
        }

        private string GetBackendUrl()
        {
            return ServerAddress + this.Request.RequestUri.AbsolutePath;
        }
    }
}