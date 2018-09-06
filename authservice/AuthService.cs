using Microsoft.Owin.Hosting;
using System;
using System.Configuration;
using System.IO;
using System.Reflection;
using System.ServiceProcess;

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
            WebApp.Start<OwinConfig>("http://localhost:" + ServicePort);
            Log.Logger.Writeline("Auth service is running");
        }
    }
}