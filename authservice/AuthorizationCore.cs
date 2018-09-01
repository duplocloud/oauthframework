using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using Log;
using System.Security.Claims;
using Newtonsoft.Json.Linq;
using System.Linq;
using System.Text;
using System.Threading;
using System.Configuration;
using System.IO;

namespace AuthService
{

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
        
        private static IStorageClient DbClient;

        private string TenantAuthTable { get; set; }
        private string TenantAuthTableKeyName = "TenantId";

        private string UserRoleTable { get; set; }
        private string UserRoleTableKeyName = "Username";

        private static Dictionary<string, TenantAuthInfo> TenantAuthInfoCache;
        private static ReaderWriterLock TenantAuthInfoCachelock = new ReaderWriterLock();
        private static int LOCK_TIMEOUT = 5000; // In ms
        
        private AuthorizationCore()
        {
            TenantAuthInfoCache = new Dictionary<string, TenantAuthInfo>();
            UserRolesCache = new Dictionary<string, UserRole>();
            DbClient = new LocalStorageClient();
                
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
            DbClient.Init(lKvps);
            ReloadCache();
        }

        private void ReloadCache()
        {
            ReloadTenantAuthCache();
            ReloadUserRoleCache();
        }

        private void ReloadTenantAuthCache()
        {
            try
            {
                TenantAuthInfoCachelock.AcquireWriterLock(LOCK_TIMEOUT);
                try
                {
                    DbClient.GetAllTenantAuthInfo(TenantAuthTable, TenantAuthInfoCache);
                }
                catch (Exception ex)
                {
                    Logger.Writeline("FAILED ReloadCache exception {0}", ex);
                    throw ex;
                }
                finally
                {
                    TenantAuthInfoCachelock.ReleaseWriterLock();
                }
            }
            catch (ApplicationException ex)
            {
                Logger.Writeline("ReloadCache Failed while trying to acquiring lock {0}", ex);
                throw ex;
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

        
    }
}
