using System;
using System.Runtime.InteropServices;
using System.Text;

namespace 密钥检测关键字符串Hook
{
    class Program
    {
        private static IntPtr _originalFunctionPtr = IntPtr.Zero;

        #region 委托定义 - 核心修改：改为 Cdecl
        // ✅ 修正：使用 ThisCall。第一个参数对应伪代码的 BYTE *this (ECX)
        // 其余 4 个参数对应 a2, a3, a4, a5
        [UnmanagedFunctionPointer(CallingConvention.ThisCall, CharSet = CharSet.Unicode)]
        private delegate int GetPID2Delegate(
            IntPtr pThis,    // 对应伪代码 BYTE *this
            IntPtr a2,       // 对应 unsigned __int16 *a2
            IntPtr a3,       // 对应 char *a3
            IntPtr a4,       // 对应 void *a4
            IntPtr a5        // 对应 const unsigned __int16 **a5
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int DelegateGetPKeyData(
            string ProductKey,
            string PkeyConfigPath,
            string MPCID,
            string pwszPKeyAlgorithm,
            IntPtr OemId,
            IntPtr OtherId,
            out string IID,
            out string Description,
            out string channel,
            out string subType,
            StringBuilder PID);
        #endregion

        #region WinAPI
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll")]
        static extern bool FreeLibrary(IntPtr hModule);
        #endregion

        private const int HOOK_OFFSET = 0x1694C;

        static void Main()
        {
            if (IntPtr.Size == 8)
            {
                Console.WriteLine("❌ 必须在 x86 模式下运行 (Project -> Properties -> Platform Target: x86)");
                Console.ReadLine();
                return;
            }

            IntPtr hModule = LoadLibrary("ProductKeyUtilities.dll");
            if (hModule == IntPtr.Zero) return;

            _originalFunctionPtr = new IntPtr(hModule.ToInt32() + HOOK_OFFSET);

            // 安装 Hook
            //IntPtr hookHandler = FastCall.WrapStdCallInFastCall(Marshal.GetFunctionPointerForDelegate(new GetPID2Delegate(MyGetPID2)));
            //new HookAPI(_originalFunctionPtr, hookHandler);

            // 初始化 Hook  ThisCall
            IntPtr hookHandler = Marshal.GetFunctionPointerForDelegate(new GetPID2Delegate(MyGetPID2));
            new HookAPI(_originalFunctionPtr, hookHandler);
            HookAPI.Install();

            Console.WriteLine("✅ Hook 已安装，正在触发 GetPKeyData...");
            Console.WriteLine($"按任意健继续，hModule地址为：0x{hModule.ToInt32():X8}"); //0x{_originalFunctionPtr.ToInt32():X8}
            Console.WriteLine("按任意健继续，_originalFunctionPtr地址为：0x" + _originalFunctionPtr.ToString("X8")); //0x{_originalFunctionPtr.ToInt32():X8}
            Console.ReadLine();

            // 触发代码
            IntPtr proc = GetProcAddress(hModule, "GetPKeyData");
            var getPKeyData = Marshal.GetDelegateForFunctionPointer<DelegateGetPKeyData>(proc);
            string productKey = "VK7JG-NPHTM-C97JM-9MPGT-3V66T";
            string configPath = AppDomain.CurrentDomain.BaseDirectory + "pkconfig_winNext.xrm-ms";

            try
            {
                getPKeyData(productKey, configPath, null, null, IntPtr.Zero, IntPtr.Zero,
                            out _, out _, out _, out _, null);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"触发异常: {ex.Message}");
            }

            //HookAPI.Unistall();
            FreeLibrary(hModule);
            Console.ReadLine();
        }

        #region Hook 回调逻辑
        private static int MyGetPID2(IntPtr pThis, IntPtr a2, IntPtr a3, IntPtr a4, IntPtr a5)
        {
            // 1. 卸载 Hook
            HookAPI.Unistall();

            // 2. 准备读取 v28
            // 我们需要知道 v28 什么时候被赋值。
            // 伪代码显示：v28 在 sub_551FABBC 调用后才有值。

            int result = 0;
            try
            {
                // 尝试寻找真正的函数指针（这里可能需要你重新核对该函数在导出表或 IDA 中的开头）
                var realFunc = Marshal.GetDelegateForFunctionPointer<GetPID2Delegate>(_originalFunctionPtr);
                result = realFunc(pThis, a2, a3, a4, a5);

                // 3. 在返回后，通过当前的 EBP 偏移读取
                // 伪代码：v28 在 [ebp-0x20]
                IntPtr currentEbp = StackHelper.GetCurrentEbp();
                IntPtr v28Addr = new IntPtr(currentEbp.ToInt32() - 0x20);

                // 检查地址是否有效
                int v28Ptr = Marshal.ReadInt32(v28Addr);
                if (v28Ptr != 0)
                {
                    Console.WriteLine("v28 捕获成功: " + Marshal.PtrToStringUni((IntPtr)v28Ptr));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("执行崩溃，可能是地址偏移或调用约定错误: " + ex.Message);
            }
            finally
            {
                HookAPI.Install();
            }
            return result;
        }
        #endregion


    }
    #region 辅助工具类 (获取 EBP)
    public static class StackHelper
    {
        private static readonly byte[] GetEbpCode = { 0x8B, 0xC5, 0xC3 }; // mov eax, ebp; ret
        private delegate IntPtr GetEbpDelegate();
        private static GetEbpDelegate _getEbp;

        static StackHelper()
        {
            IntPtr ptr = VirtualAlloc(IntPtr.Zero, (uint)GetEbpCode.Length, 0x1000, 0x40);
            Marshal.Copy(GetEbpCode, 0, ptr, GetEbpCode.Length);
            _getEbp = (GetEbpDelegate)Marshal.GetDelegateForFunctionPointer(ptr, typeof(GetEbpDelegate));
        }

        public static IntPtr GetCurrentEbp() => _getEbp();

        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAlloc(IntPtr lp, uint size, uint type, uint protect);
    }
    #endregion
}