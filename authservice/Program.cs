using System.ServiceProcess;
using System.Threading;

namespace AuthService
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            // Initialize logging
            Log.Logger.InitLogger("AuthService");
            Log.Logger.Writeline("Starting Oauth Service");
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