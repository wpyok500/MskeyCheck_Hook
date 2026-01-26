using System;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using EasyHook;

namespace KeyHook_Optimized
{
    internal class Program
    {
        #region ===== Native Delegates =====

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int GetPID2Delegate(
            IntPtr fileTimePtr,
            IntPtr mpidPtr,
            int langId,
            int dwBuildNumber,
            int unkParam,
            IntPtr dpid2Ptr);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int FnPidGenX(
            string productKey,
            string pkeyPath,
            string mpcid,
            IntPtr unknown,
            IntPtr pid2,
            IntPtr pid3,
            IntPtr pid4);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int DelegateGetPKeyData(
            string productKey,
            string pkeyConfigPath,
            string mpcid,
            string algo,
            IntPtr oemId,
            IntPtr otherId,
            out string iid,
            out string description,
            out string channel,
            out string subType,
            StringBuilder pid);

        #endregion

        #region ===== Win32 =====

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        private static extern void RtlZeroMemory(IntPtr dst, int size);

        #endregion

        #region ===== Globals =====

        private static LocalHook _hook;
        private static GetPID2Delegate _originalGetPID2;

        private static readonly ConcurrentQueue<string> _logQueue = new ConcurrentQueue<string>();
        private static readonly ManualResetEvent _exitEvent = new ManualResetEvent(false);

        private const long GET_PID2_OFFSET_X64 = 50073; // ⚠️ 与 DLL 版本强相关
        private const string PRODUCT_KEY = "VK7JG-NPHTM-C97JM-9MPGT-3V66T";
        private const string CONFIG_FILE = "pkconfig_winNext.xrm-ms";

        #endregion

        static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("=== KeyHook Optimized (x64 / EasyHook) ===\n");

            if (IntPtr.Size != 8)
            {
                Console.WriteLine("❌ 仅支持 x64 进程");
                return;
            }

            IntPtr hDll = IntPtr.Zero;
            IntPtr p1 = IntPtr.Zero, p2 = IntPtr.Zero, p3 = IntPtr.Zero;

            try
            {
                string configPath = Path.Combine(Environment.CurrentDirectory, CONFIG_FILE);
                if (!File.Exists(configPath))
                    throw new FileNotFoundException("配置文件不存在", configPath);

                hDll = LoadLibrary("ProductKeyUtilities.dll");
                if (hDll == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "DLL 加载失败");

                InstallHook(hDll);

                (p1, p2, p3) = AllocateBuffers();

                StartLogWorker();

                ParseProductKeyInfo(hDll, PRODUCT_KEY, configPath);

                CallPidGenX(hDll, PRODUCT_KEY, configPath, p1, p2, p3);

                Console.WriteLine("\n✔ 执行完成，回车退出");
                Console.ReadLine();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(ex);
                Console.ResetColor();
            }
            finally
            {
                _exitEvent.Set();
                Cleanup(hDll, p1, p2, p3);
            }
        }

        #region ===== Hook Install =====

        private static void InstallHook(IntPtr hModule)
        {
            IntPtr target = new IntPtr(hModule.ToInt64() + GET_PID2_OFFSET_X64);

            _hook = LocalHook.Create(
                target,
                new GetPID2Delegate(Hook_GetPID2),
                out _originalGetPID2);

            _hook.ThreadACL.SetExclusiveACL(Array.Empty<int>());

            Console.WriteLine($"🪝 Hook Installed @ 0x{target.ToInt64():X}");
        }

        #endregion

        #region ===== Hook Callback =====

        private static int Hook_GetPID2(
            IntPtr fileTimePtr,
            IntPtr mpidPtr,
            int langId,
            int dwBuildNumber,
            int unkParam,
            IntPtr dpid2Ptr)
        {
            try
            {
                _logQueue.Enqueue(
                    $"[GetPID2] Lang={langId}, Build={dwBuildNumber}, Unk={unkParam}");

                int ret = _originalGetPID2(
                    fileTimePtr, mpidPtr, langId, dwBuildNumber, unkParam, dpid2Ptr);

                if (ret == 0 && fileTimePtr != IntPtr.Zero)
                    ParseFileTime(fileTimePtr);

                return ret;
            }
            catch
            {
                // Hook 回调绝不允许异常外泄
                return _originalGetPID2(
                    fileTimePtr, mpidPtr, langId, dwBuildNumber, unkParam, dpid2Ptr);
            }
        }

        #endregion

        #region ===== Helpers =====

        private static void ParseFileTime(IntPtr ptr)
        {
            try
            {
                int index = Marshal.ReadInt32(ptr);
                IntPtr strPtr = Marshal.ReadIntPtr(ptr, IntPtr.Size);
                string key = Marshal.PtrToStringUni(strPtr);

                _logQueue.Enqueue($"    Index={index}, ActConfigKey={key}");
            }
            catch
            {
                _logQueue.Enqueue("    FileTime parse failed");
            }
        }

        private static (IntPtr, IntPtr, IntPtr) AllocateBuffers()
        {
            IntPtr a = Marshal.AllocHGlobal(100);
            IntPtr b = Marshal.AllocHGlobal(164);
            IntPtr c = Marshal.AllocHGlobal(1272);

            RtlZeroMemory(a, 100);
            RtlZeroMemory(b, 164);
            RtlZeroMemory(c, 1272);

            Marshal.WriteByte(a, 0, 50);
            Marshal.WriteByte(b, 0, 164);
            Marshal.WriteByte(c, 0, 248);
            Marshal.WriteByte(c, 1, 4);

            return (a, b, c);
        }

        private static void ParseProductKeyInfo(IntPtr hDll, string key, string config)
        {
            IntPtr fn = GetProcAddress(hDll, "GetPKeyData");
            if (fn == IntPtr.Zero)
                return;

            var getPKeyData = Marshal.GetDelegateForFunctionPointer<DelegateGetPKeyData>(fn);

            getPKeyData(
                key, config, null, null,
                IntPtr.Zero, IntPtr.Zero,
                out string iid,
                out string desc,
                out string channel,
                out string subType,
                new StringBuilder(256));

            _logQueue.Enqueue($"[PKey] {desc} / {channel} / {subType}");
        }

        private static void CallPidGenX(
            IntPtr hDll, string key, string config,
            IntPtr p1, IntPtr p2, IntPtr p3)
        {
            IntPtr fn = GetProcAddress(hDll, "PidGenX");
            if (fn == IntPtr.Zero)
                throw new Exception("PidGenX not found");

            var pidGenX = Marshal.GetDelegateForFunctionPointer<FnPidGenX>(fn);

            pidGenX(key, config, "55041", IntPtr.Zero, p1, p2, p3);
        }

        private static void StartLogWorker()
        {
            new Thread(() =>
            {
                while (!_exitEvent.WaitOne(50))
                {
                    while (_logQueue.TryDequeue(out var msg))
                        Console.WriteLine(msg);
                }
            })
            { IsBackground = true }.Start();
        }

        private static void Cleanup(IntPtr hDll, params IntPtr[] buffers)
        {
            _hook?.Dispose();

            foreach (var p in buffers)
                if (p != IntPtr.Zero)
                    Marshal.FreeHGlobal(p);

            if (hDll != IntPtr.Zero)
                FreeLibrary(hDll);
        }

        #endregion
    }
}
