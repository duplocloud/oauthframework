using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Log;

namespace authservice
{
    class Program
    {
        static void Main(string[] args)
        {
            // Initialize logging
            Logger.InitLogger("AuthService");
            Logger.Writeline("Starting Oauth Service");
            AuthService instance = AuthService.GetInstance();
            if (args.Length > 0)
            {
                instance.Start();
                while (!AuthService.Shutdown)
                {
                    Thread.Sleep(30000);
                }
            }
            else
            {
                ServiceBase.Run(instance);
            }
        }
    }
}
