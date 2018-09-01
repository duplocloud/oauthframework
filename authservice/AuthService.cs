using System;
using System.ServiceProcess;
using System.Threading;
using System.Collections.Generic;
using Microsoft.Owin.Hosting;
using System.Configuration;
using System.IO;
using Newtonsoft.Json;
using System.Net;
using System.Reflection;
using Log;

namespace AuthService
{
    public class AuthService : ServiceBase
    {
        public static volatile bool Shutdown;

        private AuthService()
        {
        }

        public string EngineAddress { get; set; }

        public string DefaultAdmin { get; set; }
            
        private int ServicePort
        {
            get
            {
                if (string.IsNullOrEmpty(ConfigurationManager.AppSettings["SERVICEPORT"]))
                {
                    return 60020;
                }
                return int.Parse(ConfigurationManager.AppSettings["SERVICEPORT"]);
            }
        }

        /// <summary>
        /// Signleton Instance of this class
        /// </summary>
        private static AuthService instance;

        public static AuthService Instance
        {
            get { return instance; }
        }

        private static object syncRoot = new Object();

        public static AuthService GetInstance()
        {
            if (instance == null)
            {
                lock (syncRoot)
                {
                    instance = new AuthService();
                }
            }
            return instance;
        }

        protected override void OnStart(string[] args)
        {
            this.Start();
            base.OnStart(args);
        }

        protected override void OnStop()
        {
            AuthService.Shutdown = true;
            base.OnStop();
        }
            
        public static string AssemblyDirectory
        {
            get
            {
                string codeBase = Assembly.GetExecutingAssembly().CodeBase;
                UriBuilder uri = new UriBuilder(codeBase);
                string path = Uri.UnescapeDataString(uri.Path);
                return Path.GetDirectoryName(path);
            }
        }
            

        public void Start()
        {
            EngineAddress = ConfigurationManager.AppSettings["APIENDPOINT"];
            if (string.IsNullOrEmpty(EngineAddress))
            {
                string lMsg = string.Format("API endpoint is empty, a server should be configured for forwarding the requests");
                Logger.Writeline(lMsg);
                throw new InvalidDataException(lMsg);
            }

            string lAuthTable = ConfigurationManager.AppSettings["TenantAuthDDBTableName"];
            string lUserTable = ConfigurationManager.AppSettings["UserRoleDDBTableName"];
            DefaultAdmin = ConfigurationManager.AppSettings["DEFAULTADMIN"];
            AuthorizationCore.GetInstance().Init(lAuthTable, lUserTable);

            WebApp.Start<OwinConfig>("https://*:" + ServicePort);
            Logger.Writeline("Auth service is running");
        }
    }
}
