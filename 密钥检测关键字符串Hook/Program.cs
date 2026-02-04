using System;
using System.Runtime.InteropServices;
using System.Text;

namespace 密钥检测关键字符串优化版
{
    class Program
    {
        #region 委托定义
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int fnPidGenX(string ProductKey, string PkeyPath, string MPCID, IntPtr UnknownUsage, IntPtr PID2, IntPtr PID3, IntPtr PID4);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate int DelegateGetPKeyData(
            string ProductKey,       // wchar_t *Str
            string PKeyConfigPath,   // __int64 a2
            string MPCID,            // const wchar_t *a3
            string Algorithm,        // __int64 a4
            IntPtr OemId,            // __int64 a5
            IntPtr OtherId,          // _QWORD *a6 (通常作为保留或额外参数)
            out string IID,          // _QWORD *a7
            out string Description,  // _QWORD *a8
            out string Channel,      // _QWORD *a9
            out string SubType,      // (这是你之前代码中有的，但 C++ 签名里似乎少了一位？)
            StringBuilder PID        // __int64 a10
        );

        #endregion

        #region API 导入
        [DllImport("kernel32.dll")]
        internal static extern bool RtlZeroMemory(IntPtr destination, int length);

        [DllImport("kernel32", SetLastError = true)]
        internal static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool FreeLibrary(IntPtr hModule);
        #endregion

        private static string ProductKey = "6DDRB-NYW97-7B67B-VPJJP-J4473";

        static void Main(string[] args)
        {
            string pkeyConfigXml = AppDomain.CurrentDomain.BaseDirectory + "pkconfig_winNext.xrm-ms";

            // 1. 预分配非托管内存
            IntPtr pid2Ptr = Marshal.AllocHGlobal(100);
            IntPtr pid3Ptr = Marshal.AllocHGlobal(164);
            IntPtr pid4Ptr = Marshal.AllocHGlobal(1272);
            IntPtr hModule = IntPtr.Zero;

            try
            {
                // 初始化内存
                RtlZeroMemory(pid2Ptr, 100);
                RtlZeroMemory(pid3Ptr, 164);
                RtlZeroMemory(pid4Ptr, 1272);

                // 2. 加载 DLL
                hModule = LoadLibrary("ProductKeyUtilities.dll");
                if (hModule == IntPtr.Zero)
                {
                    Console.WriteLine("无法加载 pidgenx.dll，请检查文件是否存在。");
                    return;
                }

                // 3. 执行 GetPKeyData (获取详细信息)
                IntPtr addrGetPKeyData = GetProcAddress(hModule, "GetPKeyData");
                if (addrGetPKeyData != IntPtr.Zero)
                {
                    var getPKeyData = Marshal.GetDelegateForFunctionPointer<DelegateGetPKeyData>(addrGetPKeyData);
                    StringBuilder pidBuffer = new StringBuilder(256); // 建议预分配容量

                    int result = getPKeyData(ProductKey, pkeyConfigXml, null, null, IntPtr.Zero, IntPtr.Zero,
                        out string iid, out string desc, out string channel, out string subType, pidBuffer);

                    if (result == 0)
                    {
                        Console.WriteLine($"--- 密钥信息 ---");
                        Console.WriteLine($"描述: {desc}");
                        Console.WriteLine($"渠道: {channel}");
                        Console.WriteLine($"子类型: {subType}");
                        Console.WriteLine($"安装ID: {iid}");
                    }
                    else
                    {
                        Console.WriteLine($"GetPKeyData 失败，错误码: 0x{result:X8}");
                    }
                }

                // 4. 执行 PidGenX (核心验证)
                IntPtr addrPidGenX = GetProcAddress(hModule, "PidGenX");
                if (addrPidGenX != IntPtr.Zero)
                {
                    var pidGenX = Marshal.GetDelegateForFunctionPointer<fnPidGenX>(addrPidGenX);

                    // 填充缓冲区头部长度信息 (根据原代码逻辑)
                    Marshal.WriteInt32(pid2Ptr, 0, 50);
                    Marshal.WriteInt32(pid3Ptr, 0, 164);

                    int num = pidGenX(ProductKey, pkeyConfigXml, "55041", IntPtr.Zero, pid2Ptr, pid3Ptr, pid4Ptr);
                    Console.WriteLine($"\nPidGenX 验证结果: {(num == 0 ? "有效" : "无效")} (错误码: 0x{num:X8})");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"运行异常: {ex.Message}");
            }
            finally
            {
                // 5. 关键：释放资源，防止内存泄漏
                if (pid2Ptr != IntPtr.Zero) Marshal.FreeHGlobal(pid2Ptr);
                if (pid3Ptr != IntPtr.Zero) Marshal.FreeHGlobal(pid3Ptr);
                if (pid4Ptr != IntPtr.Zero) Marshal.FreeHGlobal(pid4Ptr);
                if (hModule != IntPtr.Zero) FreeLibrary(hModule);
            }

            Console.WriteLine("\n按任意键退出...");
            Console.ReadKey();
        }
    }
}