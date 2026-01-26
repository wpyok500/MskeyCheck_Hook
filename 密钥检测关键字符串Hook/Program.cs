using EasyHook;
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace 密钥检测关键字符串Hook
{
    class Program
    {
        #region ===== 委托定义（和你的代码完全一致）=====
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int GetPID2Delegate(IntPtr FileTime, IntPtr MPID, int LangId, int dwBuildNumber, int unk, IntPtr DPID2);


        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int fnPidGenX(string ProuctKey, string PkeyPath, string MPCID, IntPtr UnknownUsage, IntPtr PID2, IntPtr PID3, IntPtr PID4);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int DelegateGetPKeyData(string ProductKey, string PkeyConfigPath, string MPCID, string pwszPKeyAlgorithm, IntPtr OemId, IntPtr OtherId, out string IID, out string Description, out string channel, out string subType, StringBuilder PID);
        #endregion

        #region ===== Win32 API（和你的代码完全一致）=====
        [DllImport("kernel32.dll")]
        internal static extern bool RtlZeroMemory(IntPtr destination, int length);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool SetDllDirectory(string lpPathName);

        [DllImport("kernel32", SetLastError = true)]
        internal static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("Kernel32.dll")]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll")]
        internal static extern bool FreeLibrary(IntPtr hModule);
        #endregion

        #region ===== EasyHook 全局变量 =====
        private static LocalHook _getPID2Hook;
        private static GetPID2Delegate _originalGetPID2;
        private static IntPtr _hModuleBase = IntPtr.Zero;
        // ✅ 使用你验证过的偏移（50073/55041/50252 任选其一）
        private const int GET_PID2_OFFSET = 50073;
        #endregion

        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            string ProductKeys = "VK7JG-NPHTM-C97JM-9MPGT-3V66T";
            string pkeyconfigxml = Environment.CurrentDirectory + "\\pkconfig_winNext.xrm-ms";

            // 1. 分配并初始化缓冲区（和你的代码完全一致）
            IntPtr intPtr = Marshal.AllocHGlobal(100);
            RtlZeroMemory(intPtr, 50);
            Marshal.WriteByte(intPtr, 0, 50);

            IntPtr intPtr2 = Marshal.AllocHGlobal(164);
            RtlZeroMemory(intPtr2, 164);
            Marshal.WriteByte(intPtr2, 0, 164);

            IntPtr intPtr3 = Marshal.AllocHGlobal(1272);
            RtlZeroMemory(intPtr3, 1272);
            Marshal.WriteByte(intPtr3, 0, 248);
            Marshal.WriteByte(intPtr3, 1, 4);

            try
            {
                // 2. 加载 DLL（和你的代码完全一致）
                _hModuleBase = LoadLibrary("ProductKeyUtilities.dll");
                if (_hModuleBase == IntPtr.Zero)
                {
                    Console.WriteLine("❌ 加载 ProductKeyUtilities.dll 失败");
                    return;
                }
                Console.WriteLine($"✅ DLL 加载成功，基地址：0x{_hModuleBase.ToInt32():X8}");

                // 3. 调用 GetPKeyData（和你的代码完全一致）
                IntPtr procAddress1 = GetProcAddress(_hModuleBase, "GetPKeyData");
                if (procAddress1 == IntPtr.Zero)
                {
                    Console.WriteLine("❌ 获取 GetPKeyData 地址失败");
                    return;
                }

                DelegateGetPKeyData getPKeyData = Marshal.GetDelegateForFunctionPointer<DelegateGetPKeyData>(procAddress1);
                string IID, Description, channel, subType;
                StringBuilder PID = new StringBuilder(256); // 修复空指针问题
                int num1 = getPKeyData(ProductKeys, pkeyconfigxml, null, null, IntPtr.Zero, IntPtr.Zero, out IID, out Description, out channel, out subType, PID);

                Console.WriteLine($"\n✅ GetPKeyData 调用成功");
                Console.WriteLine($"IID: {IID}");
                Console.WriteLine($"描述: {Description}");
                Console.WriteLine($"渠道: {channel}");
                Console.WriteLine($"子类型: {subType}");
                Console.WriteLine($"PID: {PID}");

                // 4. 使用 EasyHook 安装 Hook（核心适配）
                Console.WriteLine($"\n📌 开始 Hook GetPID2（偏移：{GET_PID2_OFFSET}）");
                // 关键：用 ToInt32() 计算目标地址（和你的代码一致）
                IntPtr targetAddr = new IntPtr(_hModuleBase.ToInt32() + GET_PID2_OFFSET);
                Console.WriteLine($"目标地址：0x{targetAddr.ToInt32():X8}");

                // 创建 EasyHook Hook（绑定回调）
                _getPID2Hook = LocalHook.Create(
                    targetAddr,
                    new GetPID2Delegate(MyGetPID2_Callback), // 你的回调函数
                    null);

                // 启用 Hook：拦截所有线程
                _getPID2Hook.ThreadACL.SetExclusiveACL(new int[0]);
                // 绑定原函数委托（用于回调中调用原生函数）
                _originalGetPID2 = Marshal.GetDelegateForFunctionPointer<GetPID2Delegate>(targetAddr);

                Console.WriteLine($"✅ EasyHook 安装成功");

                // 5. 调用 PidGenX 触发 Hook（和你的代码完全一致）
                IntPtr procAddress = GetProcAddress(_hModuleBase, "PidGenX");
                if (procAddress == IntPtr.Zero)
                {
                    Console.WriteLine("❌ 获取 PidGenX 地址失败");
                    return;
                }

                fnPidGenX pidGenX = Marshal.GetDelegateForFunctionPointer<fnPidGenX>(procAddress);
                int num = pidGenX(ProductKeys, pkeyconfigxml, "55041", IntPtr.Zero, intPtr, intPtr2, intPtr3);
                Console.WriteLine($"\n✅ PidGenX 调用完成，返回值：{num}");

                // 6. 卸载 EasyHook
                _getPID2Hook.Dispose();
                Console.WriteLine($"✅ EasyHook 已卸载");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\n❌ 执行异常：{ex.Message}");
                Console.ResetColor();
            }
            finally
            {
                // 释放缓冲区
                if (intPtr != IntPtr.Zero) Marshal.FreeHGlobal(intPtr);
                if (intPtr2 != IntPtr.Zero) Marshal.FreeHGlobal(intPtr2);
                if (intPtr3 != IntPtr.Zero) Marshal.FreeHGlobal(intPtr3);
                // 释放 DLL
                if (_hModuleBase != IntPtr.Zero) FreeLibrary(_hModuleBase);
            }

            Console.WriteLine("\n✔ 程序执行完成，按回车退出...");
            Console.ReadLine();
        }

        #region ===== EasyHook 回调函数（兼容你的解析逻辑）=====
       

        // 2. 修正后的回调逻辑
        private static int MyGetPID2_Callback(IntPtr FileTime, IntPtr MPID, int LangId, int dwBuildNumber, int unk, IntPtr DPID2)
        {
            // 关键：打印进入日志，确认 Hook 确实触发了
            Console.WriteLine($"\n[HOOK] ⚡ GetPID2 被调用! 参数: LangId={LangId}, Build={dwBuildNumber}");

            int num = -1;
            try
            {
                // 使用 OriginalGetPID2 委托调用原函数
                // 确保 OriginalGetPID2 是在 Main 中通过 Marshal.GetDelegateForFunctionPointer 获取的
                num = _originalGetPID2(FileTime, MPID, LangId, dwBuildNumber, unk, DPID2);
                Console.WriteLine($"[HOOK] ✅ 原函数返回: {num}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[HOOK] ❌ 调用原函数失败 (可能是堆栈损坏): {ex.Message}");
                return -1;
            }

            // 解析逻辑
            if (FileTime != IntPtr.Zero)
            {
                try
                {
                    // 如果在此处崩溃，说明 FileTime 内存结构与我们定义的结构体不一致
                    // 先尝试手动读取前 4 字节（index）
                    int index = Marshal.ReadInt32(FileTime);

                    // 尝试读取指针偏移后的字符串
                    // 很多时候 ActConfigKey 是在结构体的偏移位置，或者是直接紧随其后的字符串
                    FileTime ft = Marshal.PtrToStructure<FileTime>(FileTime);
                    if (!string.IsNullOrEmpty(ft.ActConfigKey))
                    {
                        Console.WriteLine($"[HOOK] 🎯 成功抓取 ActConfigKey: {ft.ActConfigKey}");
                    }
                    else
                    {
                        // 兜底方案：直接把 FileTime 指针处的内存当做字符串读一下试试
                        string raw = Marshal.PtrToStringUni(new IntPtr(FileTime.ToInt64() + 4));
                        Console.WriteLine($"[HOOK] 🔍 原始内存探测: {raw}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[HOOK] ⚠️ 解析内存失败: {ex.Message}");
                }
            }

            return num;
        }
        #endregion

        #region ===== 结构体定义（和你的代码完全一致）=====
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto, Pack = 4)]
        public struct FileTime
        {
            public int index;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string ActConfigKey;
        }
        #endregion
    }
}