# wmiServSessEnum
 multithreaded .net tool that uses WMI queries to enumerate active user sessions and accounts configured to run services (even those that are stopped and disabled) on remote systems

# Usage
WmiServSessEnum can be ran in several different modes: 
- **sessions**  – output similar to other user enumeration tools, this will query the Win32_LoggedOnUser and Win32_SessionProcess WMI classes to return a list of active sessions on the remote system
-	**services** – this option will query the Win32_Service WMI class and return a list (if any) of non-default accounts configured to run services on the remote system
-	**all**(default) – runs both collection methods on each host

**Required Flags (one of the following two required)**
- **-L** - Comma seperated list of IP's / hostnames to scan.  Please don't include spaces between addresses
- **-F** - File containing a list of IP's / hostnames to scan, one per line


**Optional Flags**
- **-M** - Mode selection (options = services, sessions, all) (Default: all)
- **-U** - Username to use, if you want to use alternate credentials to run. Must use with -P and -D flags
- **-P** - Plaintext password to use, if you want to use alternate credentials to run. Must use with -U and -D flags
- **-D** - Domain to use, if you want to use alternate credentials to run (. for local domain). Must use with -U and -P flags
- **-T** - Threads to use to concurently enumerate multiple remote hosts (Default: 10)
- **-W** - Wait time, in seconds, for CimSession connect before connection timeout (Default: 10) - I wouldn't drop this number too low or you will get false negatives


Note: Designed for informational purposes only, please only use this tool on networks you own or have permission to test against.
