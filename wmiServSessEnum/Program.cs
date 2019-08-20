using System;
using System.Threading;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;
using System.Security;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace wmiServSessEnum
{
    class Program
    {
        static void Main(string[] args)
        {
            Thread th = Thread.CurrentThread;
            th.Name = "MainThread";
            var comparer = StringComparer.OrdinalIgnoreCase;
            var arguments = new Dictionary<string, string>(comparer);
            CimCredential Credentials = null;
            int maxThreads = 10;
            int timeout = 10;
            int workers, async;
            String mode = "all";
            //we create a DComSessionOptions object to force our remote connections to use DCom instead of WinRM
            DComSessionOptions SessionOptions = new DComSessionOptions();
            foreach (string argument in args)
            {
                int idx = argument.IndexOf('=');
                if (idx > 0)
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                if (argument.ToLower() == "help" || argument.ToLower() == "-h")
                {
                    help();
                    System.Environment.Exit(0);
                }
            }

            List<String> targetHosts = new List<string>();
            Console.WriteLine("");
            //gather targets, either from file or directly from commandline
            if (arguments.ContainsKey("-l"))
            {
                targetHosts = arguments["-l"].Split(',').ToList();
                if (arguments.ContainsKey("-f"))
                {
                    Console.WriteLine("Error -- please only use one targeting flag at a time (-l or -f)");
                    System.Environment.Exit(1);
                }
            }
            else if (arguments.ContainsKey("-f"))
            {
                try
                {
                    targetHosts = File.ReadAllLines(arguments["-f"]).ToList();
                }
                catch
                {
                    Console.WriteLine($"Error - the input file at {arguments["-f"]} could not be read");
                    System.Environment.Exit(2);
                }
            }
            else
            {
                Console.WriteLine("Error -- please to enter systems to target\n");
                help();
                Environment.Exit(1);
            }
            if (arguments.ContainsKey("-m"))
            {
                try
                {
                    mode = System.Enum.Parse(typeof(Modules), arguments["-m"], true).ToString();
                }
                catch
                {
                    Console.WriteLine("Error -- invalid collection mode selected");
                    System.Environment.Exit(1);
                }
            }
            if ((arguments.ContainsKey("-d")) || (arguments.ContainsKey("-u")) || (arguments.ContainsKey("-p")))
            {
                try
                {
                    SecureString securepassword = new SecureString();
                    foreach (char c in arguments["-p"])
                    {
                        securepassword.AppendChar(c);
                    }
                    Credentials = new CimCredential(PasswordAuthenticationMechanism.Default, arguments["-d"], arguments["-u"], securepassword);
                }
                catch
                {
                    Console.WriteLine("Error -- if using alternative credentials, please ensure to include domain, username, and password (use a domain of . for a local account)");
                    System.Environment.Exit(1);
                }
            }

            //get available worker threads, we dont care about async.
            ThreadPool.GetAvailableThreads(out workers, out async);
            if (arguments.ContainsKey("-t"))
            {
                if (System.Convert.ToInt32(arguments["-t"]) <= workers)
                {
                    maxThreads = System.Convert.ToInt32(arguments["-t"]);
                }
                else
                {
                    Console.WriteLine("Error - not enough available worker threads in the .net thread pool (max available = " + workers + ")");
                    System.Environment.Exit(1);
                }
            }
            Console.WriteLine(workers + " worker threads available, will use up to " + maxThreads + " threads");
            ThreadPool.SetMaxThreads(maxThreads, 1);

            //wait / timeout value for wmi connects
            if (arguments.ContainsKey("-w"))
            {
                timeout = System.Convert.ToInt32(arguments["-w"]);
            }
            TimeSpan interval = new TimeSpan(0, 0, timeout);
            SessionOptions.Timeout = interval;

            // if using CimCredential with creds not inherited from current session, we'll add to our session options
            if (Credentials != null)
            {
                SessionOptions.AddDestinationCredentials(Credentials);
            }

            Console.WriteLine("Starting collection on " + targetHosts.Count + " host(s)");
            var count = new CountdownEvent(targetHosts.Count);
            foreach (string s in targetHosts)
            {
                ThreadPool.QueueUserWorkItem(status => { wmiConnect(s, SessionOptions, mode); count.Signal(); });
            }
            count.Wait();

            Console.WriteLine("----------Collection completed, results should be displayed above----------");
        }

        static void wmiConnect(string target, DComSessionOptions SessionOptions, string mode)
        {
            CimSession Session = CimSession.Create(target, SessionOptions);
            try
            {
                if (mode.ToLower() == "all" || mode.ToLower() == "services")
                {
                    var allServices = Session.QueryInstances(@"root\cimv2", "WQL", "SELECT * FROM Win32_Service where NOT startname like '%LocalSystem%' AND NOT startname like '%NT AUTHORITY%'");
                    foreach (CimInstance service in allServices)
                    {
                        if (service.CimInstanceProperties["StartName"].ToString() != "StartName")
                        {
                            Console.WriteLine($"[+]Non-default service account found on {target}: {service.CimInstanceProperties["StartName"].Value.ToString()}");
                        }
                    }
                }

                if (mode.ToLower() == "all" || mode.ToLower() == "sessions")
                {
                    var allSessions = Session.QueryInstances(@"root\cimv2", "WQL", "SELECT * FROM Win32_LoggedOnUser");
                    var allProcesses = Session.QueryInstances(@"root\cimv2", "WQL", "SELECT * FROM Win32_SessionProcess");

                    //gets us the sessionID associated with each running process on the system, done in order to avoid showing false positives tied to stale sessions
                    List<int> processSessions = new List<int>();
                    foreach (CimInstance proc in allProcesses)
                    {
                        processSessions.Add(Int32.Parse(proc.CimInstanceProperties["antecedent"].Value.ToString().Split('"')[1]));
                    }
                    IEnumerable<int> uniqueProcessSessions = processSessions.Distinct();

                    //gets us a list of all sessions on the remote system.  This will include a variety of false positives / unwanted system sessions that we have to filter out.  Results are added to a keyed dictionary for lookups against running processes.
                    List<String> sessions = new List<String>();
                    var ses2 = new Dictionary<int, string>();
                    foreach (CimInstance session in allSessions)
                    {
                        String antecedent = session.CimInstanceProperties["antecedent"].Value.ToString();
                        String dependent = session.CimInstanceProperties["dependent"].Value.ToString();
                        String[] userDomain = antecedent.Split('"');
                        int dependentKey = Int32.Parse(dependent.Split('"')[1]);
                        if ((!userDomain[1].ToLower().Contains("dwm-")) && (!userDomain[1].ToLower().Contains("umfd-")) && (!userDomain[1].ToLower().Contains("anonymous logon")) && (!userDomain[1].ToLower().Contains("local service")) && (!userDomain[1].ToLower().Contains("network service")) && (!userDomain[1].ToLower().Equals("system")))
                        {
                            sessions.Add($"{userDomain[3]}\\{userDomain[1]}");
                            ses2.Add(dependentKey, $"{userDomain[3]}\\{userDomain[1]}");
                        }
                    }

                    //Now that we have a list of sessions and a list of all logonSessionIDs with currently active processes we can compare the two in order to get an accurate list of active sessions
                    foreach (int procSession in uniqueProcessSessions)
                    {
                        if (ses2.ContainsKey(procSession))
                        {
                            Console.WriteLine($"[+]Session found on {target}: {ses2[procSession]}");
                        }
                    }
                }
            }
            catch (CimException e)
            {
                if (e.MessageId.Contains("40004"))
                {
                    Console.WriteLine($"[-]The following host was unreachable: {target}");
                    return;
                }
                else if (e.MessageId.Contains("70005"))
                {
                    Console.WriteLine($"[-]Insufficient privileges / invalid credentials on the following host: {target}");
                    return;
                }
                else if (e.MessageId.Contains("800706"))
                {
                    Console.WriteLine($"[-]No route to the following host: {target}");
                    return;
                }
                else
                {
                    Console.WriteLine($"[-]Error - undefined error on the following host: {target} errorID: {e.MessageId}");
                    return;
                }
            }
            Session.Close();
        }

        static void help()
        {
            Console.WriteLine("\n-----------WmiSessionEnum Options-----------\n");
            Console.WriteLine("Flag usage:  -Flag=setValue\n");
            Console.WriteLine("--Required Flags--");
            Console.WriteLine("(Use one of the following)");
            Console.WriteLine("-L :: comma seperated list of IP's / hostnames to scan.  Please don't include spaces between addresses");
            Console.WriteLine("-F :: file containing a list of IP's / hostnames to scan, one per line\n");
            Console.WriteLine("--Optional Flags--");
            Console.WriteLine("-M :: Mode selection (options = services, sessions, all) (Default: all)");
            Console.WriteLine("-U :: Username to use, if not running in current user's context. Must use with -P and -D flags");
            Console.WriteLine("-P :: Plaintext password to use, if not running in current user's context. Must use with -U and -D flags");
            Console.WriteLine("-D :: Domain to use, if not running in current user's context (. for local). Must use with -U and -P flags");
            Console.WriteLine("-T :: Threads to use to concurently enumerate multiple remote hosts (Default: 10)");
            Console.WriteLine("-W :: Wait time, in seconds, for CimSession connect before connection timeout (Default: 10)");
        }
    }
}

enum Modules
{
    all, sessions, services
}