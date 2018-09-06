using Log;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using System.Xml.Serialization;

namespace ApiClient
{
    public class Utils
    {
        public static int GUID_LENGTH = Guid.Empty.ToString().Length;
        private static Random random = new Random();

        public static string GetData(string aInUrl, List<KeyValuePair<string, string>> aInHeaders = null, string aInUserAgent = null, string aInAcceptHeader = null)
        {
            string lData = string.Empty;

            Logger.Writeline("Query {0}", aInUrl);

            Uri lUri = new Uri(aInUrl);
            // Create the web request
            HttpWebRequest request = WebRequest.Create(lUri) as HttpWebRequest;
            if (!string.IsNullOrEmpty(aInAcceptHeader))
            {
                request.Accept = aInAcceptHeader;
            }

            request.Method = "GET";

            if (aInHeaders != null)
            {
                foreach (KeyValuePair<string, string> lKvp in aInHeaders)
                {
                    request.Headers.Add(lKvp.Key, lKvp.Value);
                    request.UserAgent = aInUserAgent;
                    //request.KeepAlive = false;
                }
            }

            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    Logger.Writeline("Server Returned " + response.StatusCode.ToString());
                    using (Stream stream = response.GetResponseStream())
                    {
                        if (stream != null)
                        {
                            StreamReader reader = new StreamReader(stream, Encoding.UTF8);
                            if (reader != null)
                            {
                                lData = reader.ReadToEnd();
                            }
                        }
                    }

                    Logger.Writeline("Successfully retrieved read data from stream");
                }
            }
            catch (Exception ex)
            {
                Logger.Writeline("Failed to retrieve data from server with exception {0}", ex);
                throw ex;
            }

            //Logger.Writeline("Response {0} ", lData);

            return lData;
        }

        public static string PostData<T>(
            string aInUrl,
            T aInData,
            bool aInSkipSerialization,
            List<KeyValuePair<string, string>> aInHeaders,
            string aInUserAgent,
            int aInTimeout = 10000,
            string aInContentTypeHeader = null,
            List<KeyValuePair<string, string>> aOutResponseHeaders = null)
        {
            Logger.Writeline("Post {0}", aInUrl);

            Uri lUri = new Uri(aInUrl);
            // Create the web request

            HttpWebRequest request = WebRequest.Create(lUri) as HttpWebRequest;
            request.Timeout = aInTimeout;
            request.Method = "POST";

            if (aInHeaders != null)
            {
                foreach (KeyValuePair<string, string> lKvp in aInHeaders)
                {
                    request.Headers.Add(lKvp.Key, lKvp.Value);
                    if (!string.IsNullOrEmpty(aInUserAgent))
                    {
                        request.UserAgent = aInUserAgent;
                    }
                }
            }
            if (!string.IsNullOrEmpty(aInContentTypeHeader))
            {
                request.ContentType = aInContentTypeHeader;
                return PostData<T>(aInData, aInSkipSerialization, request, true, aOutResponseHeaders);
            }
            else
            {
                return PostData<T>(aInData, aInSkipSerialization, request);
            }
        }

        public static string PostData<T>(string aInUrl, T aInData, bool aInSkipSerialization = false)
        {
            Logger.Writeline("Post {0}", aInUrl);

            Uri lUri = new Uri(aInUrl);
            // Create the web request

            HttpWebRequest request = WebRequest.Create(lUri) as HttpWebRequest;
            request.Timeout = 10000;
            request.Method = "POST";

            return PostData<T>(aInData, aInSkipSerialization, request);
        }

        public static string PutData<T>(string aInUrl, T aInData, bool aInSkipSerialization = false, List<KeyValuePair<string, string>> aInHeaders = null)
        {
            Logger.Writeline("PUT {0}", aInUrl);

            Uri lUri = new Uri(aInUrl);
            // Create the web request

            HttpWebRequest request = WebRequest.Create(lUri) as HttpWebRequest;
            request.Timeout = 10000;
            request.Method = "PUT";

            if (aInHeaders != null)
            {
                foreach (KeyValuePair<string, string> lKvp in aInHeaders)
                {
                    request.Headers.Add(lKvp.Key, lKvp.Value);
                }
            }

            return PostData<T>(aInData, aInSkipSerialization, request);
        }

        public static string PostData<T>(T aInData, bool aInSkipSerialization, HttpWebRequest request, bool aInSkipContentTypeHeader = false, List<KeyValuePair<string, string>> aOutResponseHeaders = null)
        {
            if (aInData != null && !aInSkipContentTypeHeader)
            {
                request.ContentType = "application/json";
            }
            string lData = string.Empty;
            try
            {
                if (aInData != null)
                {
                    string lSerializedData = string.Empty;
                    if (aInSkipSerialization)
                    {
                        lSerializedData = aInData as string;
                    }
                    else
                    {
                        lSerializedData = Utils.Serialize<T>(aInData);
                    }

                    byte[] byteArray = Encoding.UTF8.GetBytes(lSerializedData);
                    request.ContentLength = byteArray.Length;
                    Stream dataStream = request.GetRequestStream();
                    dataStream.Write(byteArray, 0, byteArray.Length);
                    dataStream.Close();
                }

                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    Logger.Writeline("Server Returned " + response.StatusCode.ToString());
                    using (Stream stream = response.GetResponseStream())
                    {
                        if (stream != null)
                        {
                            StreamReader reader = new StreamReader(stream, Encoding.UTF8);
                            if (reader != null)
                            {
                                lData = reader.ReadToEnd();
                            }
                        }
                    }
                    if (aOutResponseHeaders != null)
                    {
                        foreach (string lHeader in response.Headers.AllKeys)
                        {
                            aOutResponseHeaders.Add(new KeyValuePair<string, string>(lHeader, response.Headers[lHeader]));
                        }
                    }
                }
            }
            catch (WebException webEx)
            {
                if ((HttpWebResponse)webEx.Response == null)
                {
                    throw webEx;
                }
                string errMsg = string.Empty;

                using (var errorResponse = (HttpWebResponse)webEx.Response)
                {
                    using (var reader = new StreamReader(errorResponse.GetResponseStream()))
                    {
                        errMsg = reader.ReadToEnd();
                        Logger.Writeline("POST API threw an exception {0}", errMsg);
                    }
                }

                throw new InvalidDataException(errMsg);
            }
            catch (Exception ex)
            {
                Logger.Writeline("Failed Post API with exception {0}", ex);
                throw ex;
            }

            return lData;
        }

        public static void DeleteData(string aInUrl, List<KeyValuePair<string, string>> aInHeaders = null)
        {
            Logger.Writeline("Delete {0}", aInUrl);

            Uri lUri = new Uri(aInUrl);
            // Create the web request
            HttpWebRequest request = WebRequest.Create(lUri) as HttpWebRequest;

            request.Method = "DELETE";

            if (aInHeaders != null)
            {
                foreach (KeyValuePair<string, string> lKvp in aInHeaders)
                {
                    request.Headers.Add(lKvp.Key, lKvp.Value);
                }
            }

            string lData = string.Empty;
            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    Logger.Writeline("Server Returned " + response.StatusCode.ToString());
                }
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
                    Logger.Writeline("WebException in Delete API {0} status {1}", errMsg, response.StatusCode);
                }
                throw webEx;
            }
            catch (Exception ex)
            {
                Logger.Writeline("Failed Delete API with exception {0}", ex);
                throw ex;
            }
        }

        public static string Serialize<T>(T aInData)
        {
            var serializer = new JavaScriptSerializer();
            string lData = serializer.Serialize(aInData);
            return lData;
        }

        public static object Deserialize<T>(string s)
        {
            var serializer = new JavaScriptSerializer();
            object result = serializer.Deserialize<T>(s);
            return result;
        }

        public static object DeserializeXml<T>(string s)
        {
            object result;
            var serializer = new XmlSerializer(typeof(T));
            using (TextReader reader = new StringReader(s))
            {
                result = serializer.Deserialize(reader);
            }

            return result;
        }

        public static void StartProcess(string aInPath, string aInFolder, string aInArgs = null)
        {
            ProcessStartInfo stinfo = new ProcessStartInfo();
            // Assign file name
            stinfo.FileName = aInPath;
            // start the process without creating new window default is false
            stinfo.CreateNoWindow = false;
            // true to use the shell when starting the process; otherwise, the process is created directly from the executable file
            stinfo.UseShellExecute = false;
            stinfo.WorkingDirectory = aInFolder;
            stinfo.Arguments = aInArgs;
            // Creating Process class object to start process
            Process lProcess = new Process();
            lProcess.StartInfo = stinfo;
            lProcess.EnableRaisingEvents = true;
            lProcess.Exited += (sender, e) =>
            {
                Logger.Writeline("Process {0} exited with exit code {1} Time {2}", lProcess.Id, lProcess.ExitCode.ToString(), lProcess.ExitTime);
            };
            // start the process
            if (lProcess.Start())
            {
                Logger.Writeline("Launched process with pid {0} at time {1}", lProcess.Id, lProcess.StartTime);
            }
            else
            {
                Logger.Writeline("Failed to launch process ");
            }
        }

        /// <summary>
        /// Stop capture if currently running
        /// </summary>
        public static bool StopProcess(int aInPid)
        {
            try
            {
                Process p = Process.GetProcessById(aInPid);
                p.Kill();
            }
            catch (Exception ex)
            {
                Logger.Writeline("Failed to kill process {0} with exception {1}", aInPid, ex);
                return false;
            }

            return true;
        }

        public static List<string> GetIpAddresses()
        {
            List<string> localIps = new List<string>();
            IPHostEntry host;
            string localIP = string.Empty;
            host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (IPAddress ip in host.AddressList)
            {
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    if (!string.IsNullOrEmpty(ip.ToString()))
                    {
                        Logger.Writeline("IP Address is {0}", ip.ToString());
                        localIps.Add(ip.ToString());
                    }
                }
            }
            return localIps;
        }

        public static bool IsWithinSubnet(IPAddress aInAddress, string aInSubnet)
        {
            // Find the mask in IPAddress format
            string[] seps = new string[] { "\\", "/" };
            string[] lToks = aInSubnet.ToString().Split(seps, StringSplitOptions.RemoveEmptyEntries);
            if (lToks.Length != 2)
            {
                throw new InvalidDataException(string.Format("Invalid subnet {0}", aInSubnet));
            }

            IPAddress lSubnet = CreateByNetBitLength(int.Parse(lToks[1]));
            return IsInSameSubnet(aInAddress, IPAddress.Parse(lToks[0]), lSubnet);
        }

        public static void LoadLocalIps(HashSet<string> aInOutLocalIps)
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    if (!aInOutLocalIps.Contains(ip.ToString()))
                    {
                        aInOutLocalIps.Add(ip.ToString());
                    }
                }
            }
        }

        public static List<KeyValuePair<string, string>> ParseAsJson(string aInCsv)
        {
            Dictionary<string, string> values = JsonConvert.DeserializeObject<Dictionary<string, string>>(aInCsv);
            return values.ToList();
        }

        public static List<KeyValuePair<string, string>> ParseCsvToKvps(string aInCsv)
        {
            aInCsv = aInCsv.Trim();
            if (aInCsv.StartsWith("{")
                && aInCsv.EndsWith("}"))
            {
                return ParseAsJson(aInCsv);
            }

            List<KeyValuePair<string, string>> lRetVal = new List<KeyValuePair<string, string>>();

            char[] delimiter = { ',' };
            string[] lKvps = aInCsv.Split(delimiter, StringSplitOptions.RemoveEmptyEntries);
            foreach (string lKvp in lKvps)
            {
                string k = lKvp.Trim();
                char[] ldel = { '\"', '=' };
                string[] lPairs = k.Split(ldel, StringSplitOptions.RemoveEmptyEntries);
                if (lPairs.Length == 2)
                {
                    KeyValuePair<string, string> lVal = new KeyValuePair<string, string>(lPairs[0], lPairs[1]);
                    lRetVal.Add(lVal);
                }
                else
                {
                    string lMsg = string.Format("Unable to parse CSV, check this pair {0} - {1}", lKvp, lPairs.Length);
                    Logger.Writeline(lMsg);
                    throw new InvalidDataException(lMsg);
                }
            }

            return lRetVal;
        }

        public static string GetDockerEnv(Dictionary<string, string> aInEnvs)
        {
            string lRetVal = string.Empty;
            foreach (KeyValuePair<string, string> lKvp in aInEnvs)
            {
                if (string.IsNullOrEmpty(lRetVal))
                {
                    lRetVal = AppendQuotes(lKvp.Key + "=" + lKvp.Value);
                }
                else
                {
                    lRetVal = lRetVal + "," + AppendQuotes(lKvp.Key + "=" + lKvp.Value);
                }
            }
            return lRetVal;
        }

        public static string AppendQuotes(string aInval)
        {
            return "\"" + aInval + "\"";
        }

        public static void LogAndThrow(params object[] args)
        {
            string lMsg = Logger.Writeline(args);
            throw new InvalidDataException(lMsg);
        }

        public static string GetDuploUser(HttpRequestMessage aInRequest)
        {
            string lRetVal = "Unknown";
            try
            {
                if (aInRequest.Headers != null)
                {
                    IEnumerable<string> headerValues = aInRequest.Headers.GetValues("DuploUser");
                    lRetVal = headerValues.FirstOrDefault();
                }
            }
            catch (Exception ex)
            {
                Logger.Writeline("Exception: Failed to process Duplo User Header {0}", ex.Message);
            }
            return lRetVal;
        }

        private static IPAddress CreateByHostBitLength(int hostpartLength)
        {
            int hostPartLength = hostpartLength;
            int netPartLength = 32 - hostPartLength;

            if (netPartLength < 2)
            {
                throw new ArgumentException("Number of hosts is to large for IPv4");
            }

            Byte[] binaryMask = new byte[4];

            for (int i = 0; i < 4; i++)
            {
                if (i * 8 + 8 <= netPartLength)
                {
                    binaryMask[i] = 255;
                }
                else if (i * 8 > netPartLength)
                {
                    binaryMask[i] = 0;
                }
                else
                {
                    int oneLength = netPartLength - i * 8;
                    string binaryDigit =
                        String.Empty.PadLeft(oneLength, '1').PadRight(8, '0');
                    binaryMask[i] = Convert.ToByte(binaryDigit, 2);
                }
            }
            return new IPAddress(binaryMask);
        }

        private static IPAddress CreateByNetBitLength(int netpartLength)
        {
            int hostPartLength = 32 - netpartLength;
            return CreateByHostBitLength(hostPartLength);
        }

        private static IPAddress GetNetworkAddress(IPAddress address, IPAddress subnetMask)
        {
            byte[] ipAdressBytes = address.GetAddressBytes();
            byte[] subnetMaskBytes = subnetMask.GetAddressBytes();

            if (ipAdressBytes.Length != subnetMaskBytes.Length)
            {
                throw new ArgumentException("Lengths of IP address and subnet mask do not match.");
            }

            byte[] broadcastAddress = new byte[ipAdressBytes.Length];
            for (int i = 0; i < broadcastAddress.Length; i++)
            {
                broadcastAddress[i] = (byte)(ipAdressBytes[i] & (subnetMaskBytes[i]));
            }
            return new IPAddress(broadcastAddress);
        }

        private static bool IsInSameSubnet(IPAddress address2, IPAddress address, IPAddress subnetMask)
        {
            IPAddress network1 = GetNetworkAddress(address, subnetMask);
            IPAddress network2 = GetNetworkAddress(address2, subnetMask);

            return network1.Equals(network2);
        }

        public static string GetForwardedAddress(HttpRequestMessage aInRequest)
        {
            string lRetVal = string.Empty;
            try
            {
                if (aInRequest.Headers != null)
                {
                    IEnumerable<string> headerValues = aInRequest.Headers.GetValues("X-Forwarded-For");
                    string lHeader = headerValues.FirstOrDefault();
                    if (!string.IsNullOrEmpty(lHeader))
                    {
                        string[] delimiters = new string[] { "," };
                        string[] tokens = lHeader.Split(delimiters, StringSplitOptions.RemoveEmptyEntries);
                        if (tokens.Any())
                        {
                            lRetVal = tokens[0];
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Writeline("Exception: Failed to process Forwarded address {0}", ex.Message);
            }
            return lRetVal;
        }

        public static string GetClientIpAddress(HttpRequestMessage aInRequest)
        {
            string HttpContext = "MS_HttpContext";
            string RemoteEndpointMessage = "System.ServiceModel.Channels.RemoteEndpointMessageProperty";
            if (aInRequest.Properties.ContainsKey(HttpContext))
            {
                dynamic ctx = aInRequest.Properties[HttpContext];
                if (ctx != null)
                {
                    return ctx.Request.UserHostAddress;
                }
            }

            if (aInRequest.Properties.ContainsKey(RemoteEndpointMessage))
            {
                dynamic remoteEndpoint = aInRequest.Properties[RemoteEndpointMessage];
                if (remoteEndpoint != null)
                {
                    return remoteEndpoint.Address;
                }
            }

            return null;
        }

        public static string[] ParseSemicolon(string aInSubnets)
        {
            string lSubnets = aInSubnets;
            string[] delimiters = new string[] { ";" };
            string[] tokens = lSubnets.Split(delimiters, StringSplitOptions.RemoveEmptyEntries);
            return tokens;
        }

        public static string GetRandomString(int length)
        {
            const string valid = "abcdefghijklmnopqrstuvwxyz1234567890";
            StringBuilder res = new StringBuilder();
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] uintBuffer = new byte[sizeof(uint)];

                while (length-- > 0)
                {
                    rng.GetBytes(uintBuffer);
                    uint num = BitConverter.ToUInt32(uintBuffer, 0);
                    res.Append(valid[(int)(num % (uint)valid.Length)]);
                }
            }

            return res.ToString();
        }

        public static bool IsValidIp(string aInIp)
        {
            if (string.IsNullOrEmpty(aInIp)
                || (string.Compare("0.0.0.0", aInIp) == 0))
            {
                return false;
            }

            IPAddress lIp = null;
            return IPAddress.TryParse(aInIp, out lIp);
        }

        public static bool DoesRegexMatch(List<string> aInRegexes, string aInName)
        {
            bool lMatched = false;
            foreach (string strRegExp in aInRegexes)
            {
                Regex rx = new Regex(strRegExp, RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
                if (rx.IsMatch(aInName))
                {
                    lMatched = true;
                    break;
                }
            }

            return lMatched;
        }

        public static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public static bool IsValidBase64(string aInString)
        {
            try
            {
                Convert.FromBase64String(aInString);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public static string GetNextIpAddress(string ipAddress, uint increment)
        {
            byte[] addressBytes = IPAddress.Parse(ipAddress).GetAddressBytes().Reverse().ToArray();
            uint ipAsUint = BitConverter.ToUInt32(addressBytes, 0);
            var nextAddress = BitConverter.GetBytes(ipAsUint + increment);
            return String.Join(".", nextAddress.Reverse());
        }

        public static int IpAddressToInteger(IPAddress IP)
        {
            int result = 0;

            byte[] bytes = IP.GetAddressBytes();
            result = bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3];

            return result;
        }
    }
}