using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

namespace Log
{
    public class Logger
    {
        public static string LOG_FILE_NAME = "AuthService.log";
        private static string LogFilePrefix = string.Empty;
        private static string LogFileFolder = string.Empty;

        private static FileStream Filestream = null;
        private static StreamWriter Streamwriter = null;

        private static ReaderWriterLock Loggerlock = new ReaderWriterLock();
        private static int LOCK_TIMEOUT = 1000; // In ms

        private static long LOG_FILE_MAX_SIZE = 10* 1024 * 1024;
        private static long CurrentFileLength = 0;
        private static int LOG_FILE_MAX_COUNT = 10;

        public static void InitLogger(string fileName, bool aInLocalDir=false)
        {
            if (string.IsNullOrEmpty(Logger.LogFilePrefix))
            {
                Logger.LogFilePrefix = fileName;
            }

            string lTime = DateTime.Now.ToString("MM-dd-HH-mm-ss");
            LOG_FILE_NAME = Logger.LogFilePrefix + "." + lTime + ".log";
            InitLogger(aInLocalDir);
        }

        public static void InitLogger(bool aInLocalDir)
        {
            Logger.CurrentFileLength = 0;

            string logFile = string.Empty;

            if(string.IsNullOrEmpty(Logger.LogFileFolder))
            {
                if (!aInLocalDir)
                {
                    string appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                    Logger.LogFileFolder = appData;
                }
                else
                {
                    string lLogPath = Path.Combine(Directory.GetCurrentDirectory(), "Logs");
                    if (!Directory.Exists(lLogPath))
                    {
                        Directory.CreateDirectory(lLogPath);
                    }

                    Logger.LogFileFolder = lLogPath;
                }
            }

            logFile = Path.Combine(Logger.LogFileFolder, LOG_FILE_NAME);

            if (Filestream == null)
            {
                Filestream = new FileStream(logFile, FileMode.Create, FileAccess.ReadWrite);
                if (Streamwriter == null)
                {
                    Streamwriter = new StreamWriter(Filestream);
                }
                Streamwriter.AutoFlush = true;
                Console.SetOut(Streamwriter);
                Console.SetError(Streamwriter);
            }

            PruneExtraLogs();
        }

        public static void CloseLogger()
        {
            if (Filestream != null)
            {
                // Write string at start of file.
                if (Streamwriter != null)
                {
                    Streamwriter.Close();
                    Streamwriter = null;
                    CurrentFileLength = 0;
                }
                Filestream.Close();
                Filestream = null;
            }
        }

        public static string Writeline(params object[] args)
        {
            if (args.Length == 0)
            {
                return string.Empty;
            }

            String finalString = string.Empty;

            finalString = String.Format("{0} - {1} ", DateTime.Now, Thread.CurrentThread.ManagedThreadId);
            finalString += args[0];
            for (int i = 1; i < args.Length; i++)
            {
                int j = i - 1;
                string tempString = "{" + j.ToString() + "}";
                string val = (args[i] != null) ? args[i].ToString() : string.Empty;
                finalString = finalString.Replace(tempString, val);
            }

            try
            {
                Loggerlock.AcquireWriterLock(LOCK_TIMEOUT);
                try
                {
                    if ((Filestream == null) || (Streamwriter == null))
                    {
                        return string.Empty;
                    }

                    Console.WriteLine(finalString);
                    Logger.CurrentFileLength = Logger.CurrentFileLength + finalString.Length;

                    if (Logger.CurrentFileLength > LOG_FILE_MAX_SIZE)
                    {
                        Console.WriteLine(" -------------- Rolling over log ----------------------- ");
                        CloseLogger();
                        InitLogger(Logger.LogFilePrefix);
                    }
                }
                finally
                {
                    Loggerlock.ReleaseWriterLock();
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }

            return finalString;
        }

        private static void PruneExtraLogs()
        {
            //Console.WriteLine("Pruning extra log files if needed");
            try
            {
                DirectoryInfo lDirInfo = new DirectoryInfo(Logger.LogFileFolder);
                FileInfo[] lFiles = lDirInfo.GetFiles(
                                        Logger.LogFilePrefix + "*.log",
                                        SearchOption.TopDirectoryOnly).OrderByDescending(fl => fl.CreationTime).ToArray();
                if (lFiles.Count() > LOG_FILE_MAX_COUNT)
                {
                    int lIndex = lFiles.Count() - 1;
              //      Console.WriteLine("Deleting log file {0}", lFiles[lIndex].FullName);
                    File.Delete(lFiles[lIndex].FullName);
                }
                else
                {
                //    Console.WriteLine("Current log file count {0}", lFiles.Count());
                }
            }
            catch (Exception ex)
            {
                //Console.WriteLine("Pruning extra log files files failed with exception {0}", ex);
                throw ex;
            }
        }
    }
}