using ApiClient;
using Log;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Web.Http;

namespace AuthService
{
    public class ESData
    {
        public string timestamp { get; set; }

        public string Tenant { get; set; }

        public string TriggeringUser { get; set; }

        public string Action { get; set; }

        public string Api { get; set; }

        public string TxtData { get; set; }

        public ESData()
        {
            timestamp = DateTime.UtcNow.ToString();
        }
    }

    public partial class AuthorizationCore
    {
        public static string CLAIM_IDENTITY_TYPE = "Email";

        /// <summary>
        /// Signleton Instance of this class
        /// </summary>
        private static AuthorizationCore instance;

        public static AuthorizationCore Instance
        {
            get { return instance; }
        }

        private static object syncRoot = new Object();

        public static AuthorizationCore GetInstance()
        {
            if (instance == null)
            {
                lock (syncRoot)
                {
                    instance = new AuthorizationCore();
                }
            }
            return instance;
        }

        private string ServerAddress
        {
            get { return AuthService.GetInstance().EngineAddress; }
        }

        public bool BlockTenantAuditAccess
        {
            get
            {
                if (string.Compare(ConfigurationManager.AppSettings["BLOCKTENANTAUDITACCESS"], "true", true) == 0)
                {
                    return true;
                }
                return false;
            }
        }

        public string LogHarvestorUrl
        {
            get
            {
                return ConfigurationManager.AppSettings["LOGHARVESTORURL"];
            }
        }

        public string AuditorUrl
        {
            get
            {
                return ConfigurationManager.AppSettings["AUDITORURL"];
            }
        }

        //private static IStorageClient DbClient;

        private string TenantAuthTable { get; set; }
        private string TenantAuthTableKeyName = "TenantId";

        private string UserRoleTable { get; set; }
        private string UserRoleTableKeyName = "Username";

        //private static Dictionary<string, TenantAuthInfo> TenantAuthInfoCache;
        private static ReaderWriterLock TenantAuthInfoCachelock = new ReaderWriterLock();

        //private static int LOCK_TIMEOUT = 5000; // In ms

        private AuthorizationCore()
        {
            //TenantAuthInfoCache = new Dictionary<string, TenantAuthInfo>();
            //UserRolesCache = new Dictionary<string, UserRole>();
            //if (!OAuthService.Instance.DISABLE_AWS_CLOUD)
            //{
            //    DbClient = new StorageClient();
            //}
            //else
            //{
            //    DbClient = new LocalStorageClient();
            //}
        }

        public void Init(string aInTenantAuthTable, string aInUserRoleTable)
        {
            TenantAuthTable = aInTenantAuthTable;
            UserRoleTable = aInUserRoleTable;
            KeyValuePair<string, string> lTenantAuthTable = new KeyValuePair<string, string>(TenantAuthTable, TenantAuthTableKeyName);
            KeyValuePair<string, string> lUserRoleTable = new KeyValuePair<string, string>(UserRoleTable, UserRoleTableKeyName);
            List<KeyValuePair<string, string>> lKvps = new List<KeyValuePair<string, string>>();
            lKvps.Add(lTenantAuthTable);
            lKvps.Add(lUserRoleTable);
            //DbClient.Init(lKvps);
        }

        public string GetUsernameFromClaims(IEnumerable<Claim> aInClaims)
        {
            string lUsername = string.Empty;
            foreach (Claim lClaim in aInClaims)
            {
                if (lClaim.Type == CLAIM_IDENTITY_TYPE)
                {
                    lUsername = lClaim.Value;
                    break;
                }
            }
            if (!string.IsNullOrEmpty(lUsername))
            {
                lUsername = lUsername.ToLower();
            }
            return lUsername;
        }

        public static HttpResponseException ThrowResponseException(HttpRequestMessage request, HttpStatusCode statusCode, string message, string errorResourceCode = null)
        {
            return new HttpResponseException(
             new HttpResponseMessage(statusCode)
             {
                 Content = new StringContent(message)
             });
        }

        public void GetDuploUserHeader(List<KeyValuePair<string, string>> aInOutHeaders)
        {
            string lUserName = GetUsernameFromClaims(ClaimsPrincipal.Current.Claims);
            aInOutHeaders.Add(new KeyValuePair<string, string>("DuploUser", lUserName));
        }

        public static void AddData(
            string aInAccountName,
            string aInUser,
            string aInAction,
            string aInApi,
            string aInJsonData)
        {
            string ESEndpoint = ConfigurationManager.AppSettings["ElasticSearchEndpoint"];
            if (string.IsNullOrEmpty(ESEndpoint))
            {
                return;
            }

            string lEsDataStr = string.Empty;
            try
            {
                ESData lEsData = new ESData();
                lEsData.Tenant = aInAccountName;
                lEsData.TriggeringUser = aInUser;
                lEsData.Action = aInAction;
                lEsData.Api = aInApi;
                lEsDataStr = Utils.Serialize<ESData>(lEsData);
                if (string.IsNullOrEmpty(aInJsonData))
                {
                    aInJsonData = "{}";
                }

                lEsDataStr = lEsDataStr.TrimEnd();
                lEsDataStr = lEsDataStr.TrimEnd('}');
                lEsDataStr = lEsDataStr + ", \"Data\":" + aInJsonData + "}";
                string lUrl = ESEndpoint + "/auth/" + aInApi;
                Utils.PostData<string>(lUrl, lEsDataStr, true, null, string.Empty, 3000);
            }
            catch (Exception ex)
            {
                Logger.Writeline("Failed to update audit information {0} in Elastic Search with exception {1}", lEsDataStr, ex.Message);
            }
        }
    }
}