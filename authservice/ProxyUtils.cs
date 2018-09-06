using ApiClient;
using Log;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;

namespace AuthService
{
    public class ProxyUtils
    {
        public static string PostData(HttpRequestMessage aInRequest, string aInBackendUrl, string aInData)
        {
            Logger.Writeline("POST API Url {0} body {1}", aInBackendUrl, aInData);
            try
            {
                List<KeyValuePair<string, string>> aInHeaders = new List<KeyValuePair<string, string>>();
                AuthorizationCore.Instance.GetDuploUserHeader(aInHeaders);

                return Utils.PostData<string>(aInBackendUrl, aInData, true, aInHeaders, string.Empty);
            }
            catch (Exception ex)
            {
                Logger.Writeline("POST failed {0}", ex.Message);
                throw AuthorizationCore.ThrowResponseException(aInRequest, HttpStatusCode.BadRequest, ex.Message);
            }
        }

        public static JToken GetProxy(string aInBackendUrl)
        {
            Logger.Writeline("Proxying GET call {0}", aInBackendUrl);
            try
            {
                List<KeyValuePair<string, string>> aInHeaders = new List<KeyValuePair<string, string>>();
                AuthorizationCore.Instance.GetDuploUserHeader(aInHeaders);
                string lResult = Utils.GetData(aInBackendUrl, aInHeaders);
                JToken lObj = JRaw.Parse(lResult);
                return lObj;
            }
            catch (WebException webEx)
            {
                if ((HttpWebResponse)webEx.Response == null)
                {
                    throw webEx;
                }

                using (HttpWebResponse response = (HttpWebResponse)webEx.Response)
                {
                    string errMsg = webEx.ToString();
                    Logger.Writeline("WebException in GET API {0} status {1}", errMsg, response.StatusCode);
                }
                throw webEx;
            }
            catch (Exception ex)
            {
                Logger.Writeline("Failed GET API with exception {0}", ex);
                throw ex;
            }
        }

        public static JToken PostProxy(HttpRequestMessage aInRequest, string aInBackendUrl)
        {
            if (aInRequest.Content == null)
            {
                return null;
            }

            JToken lObj = null;
            string jsonInput = string.Empty;
            jsonInput = aInRequest.Content.ReadAsStringAsync().Result;
            if (!string.IsNullOrEmpty(jsonInput))
            {
                lObj = JRaw.Parse(jsonInput);
                jsonInput = lObj.ToString(Newtonsoft.Json.Formatting.None);
            }

            string lResult = ProxyUtils.PostData(aInRequest, aInBackendUrl, jsonInput);
            if (!string.IsNullOrEmpty(lResult))
            {
                lObj = JRaw.Parse(lResult);
                return lObj;
            }
            else
            {
                return null;
            }
        }
    }
}