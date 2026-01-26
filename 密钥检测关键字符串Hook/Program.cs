using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using EasyHook;

namespace 密钥检测关键字符串Hook
{
    class Program
    {
        // 定义目标函数的委托（匹配原始函数的调用约定和参数）
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int GetPID2Delegate(IntPtr FileTime, IntPtr MPID, int LangId, int dwBuildNumber, int unk, IntPtr DPID2);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int fnPidGenX(string ProuctKey, string PkeyPath, string MPCID, IntPtr UnknownUsage, IntPtr PID2, IntPtr PID3, IntPtr PID4);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int DelegateGetPKeyData(string ProductKey, string PkeyConfigPath, string MPCID, string pwszPKeyAlgorithm, IntPtr OemId, IntPtr OtherId, out string IID, out string Description, out string channel, out string subType, StringBuilder PID);

        // Windows API 导入
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool RtlZeroMemory(IntPtr destination, int length);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("Kernel32.dll", SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll")]
        internal static extern bool FreeLibrary(IntPtr hModule);

        // Hook 句柄和原始函数委托
        private static LocalHook _getPID2Hook = null;
        private static GetPID2Delegate OriginalGetPID2 = null;
        private static IntPtr _hModule = IntPtr.Zero;

        static void Main(string[] args)
        {
            // 配置参数（根据实际情况修改）
            string productKey = "VK7JG-NPHTM-C97JM-9MPGT-3V66T";
            string configPath = System.IO.Path.Combine(Environment.CurrentDirectory, "pkconfig_winNext.xrm-ms");
            string dllPath = "ProductKeyUtilities.dll";
            string targetFunctionName = "GetPID2"; // 要Hook的函数名

            try
            {
                // 1. 加载目标DLL
                _hModule = LoadLibrary(dllPath);
                if (_hModule == IntPtr.Zero)
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine($"❌ 加载DLL失败！错误码: {errorCode}, 描述: {new Win32Exception(errorCode).Message}");
                    return;
                }
                Console.WriteLine($"✅ DLL加载成功，基地址: 0x{_hModule.ToString("X")}");

                // 2. 自动获取GetPID2函数地址（核心优化点）
                IntPtr targetAddress = GetProcAddress(_hModule, targetFunctionName);
                if (targetAddress == IntPtr.Zero)
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine($"❌ 未找到导出函数 {targetFunctionName}！错误码: {errorCode}");
                    Console.WriteLine("👉 请用x64dbg通过特征字符串定位该函数的正确偏移，步骤如下：");
                    Console.WriteLine("   1. 打开x64dbg → Load DLL → 选择ProductKeyUtilities.dll");
                    Console.WriteLine("   2. 按Ctrl+S → 搜索String references → 输入ActConfigKey/PID等特征字符串");
                    Console.WriteLine("   3. 定位到函数后，记录RVA（偏移），替换下方的fallbackOffset值");

                    // 备用方案：手动输入偏移（仅当函数未导出时使用）
                    int fallbackOffset = 50073; // 替换为你逆向得到的正确偏移
                    targetAddress = new IntPtr(_hModule.ToInt64() + fallbackOffset);
                    Console.WriteLine($"⚠️  使用备用偏移 {fallbackOffset}，目标地址: 0x{targetAddress.ToString("X")}");
                }
                else
                {
                    Console.WriteLine($"✅ 找到 {targetFunctionName} 导出函数，地址: 0x{targetAddress.ToString("X")}");
                }

                // 3. 创建并激活Hook
                _getPID2Hook = LocalHook.Create(
                    targetAddress,
                    new GetPID2Delegate(MyGetPID2_Hooked),
                    null);
                _getPID2Hook.ThreadACL.SetInclusiveACL(new int[] { 0 });
                Console.WriteLine($"✅ {targetFunctionName} Hook激活成功");

                // 保存原始函数委托
                OriginalGetPID2 = Marshal.GetDelegateForFunctionPointer<GetPID2Delegate>(targetAddress);

                // 4. 调用GetPKeyData（触发Hook）
                CallGetPKeyData(productKey, configPath);

                // 5. 调用PidGenX（优化参数，减少错误）
                CallPidGenX(productKey, configPath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ 执行异常: {ex.Message}\n堆栈: {ex.StackTrace}");
            }
            finally
            {
                // 清理资源
                _getPID2Hook?.Dispose();
                if (_hModule != IntPtr.Zero) FreeLibrary(_hModule);
                Console.WriteLine("\n✅ 资源已清理完成");
            }

            Console.WriteLine("\n按任意键退出...");
            Console.ReadLine();
        }

        /// <summary>
        /// 封装GetPKeyData调用逻辑
        /// </summary>
        private static void CallGetPKeyData(string productKey, string configPath)
        {
            Console.WriteLine("\n===== 调用GetPKeyData =====");
            IntPtr procAddr = GetProcAddress(_hModule, "GetPKeyData");
            if (procAddr == IntPtr.Zero)
            {
                Console.WriteLine("❌ 未找到GetPKeyData导出函数");
                return;
            }

            DelegateGetPKeyData getPKeyData = Marshal.GetDelegateForFunctionPointer<DelegateGetPKeyData>(procAddr);
            string IID = "", Description = "", channel = "", subType = "";
            StringBuilder pidSb = new StringBuilder(256);

            try
            {
                int result = getPKeyData(
                    productKey,
                    configPath,
                    null,
                    null,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    out IID,
                    out Description,
                    out channel,
                    out subType,
                    pidSb);

                Console.WriteLine($"✅ GetPKeyData调用结果: {result}");
                Console.WriteLine($"   IID: {IID}");
                Console.WriteLine($"   Description: {Description}");
                Console.WriteLine($"   channel: {channel}");
                Console.WriteLine($"   subType: {subType}");
                Console.WriteLine($"   PID: {pidSb.ToString()}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ GetPKeyData调用异常: {ex.Message}");
            }
        }

        /// <summary>
        /// 封装PidGenX调用逻辑（优化参数）
        /// </summary>
        private static void CallPidGenX(string productKey, string configPath)
        {
            Console.WriteLine("\n===== 调用PidGenX =====");
            IntPtr procAddr = GetProcAddress(_hModule, "PidGenX");
            if (procAddr == IntPtr.Zero)
            {
                Console.WriteLine("❌ 未找到PidGenX导出函数");
                return;
            }

            fnPidGenX pidGenX = Marshal.GetDelegateForFunctionPointer<fnPidGenX>(procAddr);
            IntPtr p1 = IntPtr.Zero, p2 = IntPtr.Zero, p3 = IntPtr.Zero;

            try
            {
                // 分配内存并清空
                p1 = Marshal.AllocHGlobal(100); RtlZeroMemory(p1, 100);
                p2 = Marshal.AllocHGlobal(164); RtlZeroMemory(p2, 164);
                p3 = Marshal.AllocHGlobal(1272); RtlZeroMemory(p3, 1272);

                // 优化MPCID参数（根据配置文件调整，这里用通用值）
                string mpcid = "55040"; // 替换为与你的密钥/配置匹配的MPCID
                int result = pidGenX(productKey, configPath, mpcid, IntPtr.Zero, p1, p2, p3);

                Console.WriteLine($"✅ PidGenX调用结果: {result}");
                // 解析返回的内存数据
                string p1Data = Marshal.PtrToStringUni(p1, 50)?.Trim('\0') ?? "空";
                string p2Data = Marshal.PtrToStringUni(p2, 82)?.Trim('\0') ?? "空";
                Console.WriteLine($"   p1数据: {p1Data}");
                Console.WriteLine($"   p2数据: {p2Data}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ PidGenX调用异常: {ex.Message}");
            }
            finally
            {
                // 释放非托管内存
                if (p1 != IntPtr.Zero) Marshal.FreeHGlobal(p1);
                if (p2 != IntPtr.Zero) Marshal.FreeHGlobal(p2);
                if (p3 != IntPtr.Zero) Marshal.FreeHGlobal(p3);
            }
        }

        /// <summary>
        /// GetPID2函数的Hook回调（增强日志）
        /// </summary>
        private static int MyGetPID2_Hooked(IntPtr FileTimePtr, IntPtr MPID, int LangId, int dwBuildNumber, int unk, IntPtr DPID2)
        {
            try
            {
                // 高亮打印Hook触发日志
                Console.WriteLine("\n=====================================");
                Console.WriteLine("🔥 MyGetPID2_Hooked 被触发！");
                Console.WriteLine("=====================================");
                Console.WriteLine($"   参数: LangId={LangId}, dwBuildNumber={dwBuildNumber}, unk={unk}");

                // 调用原始函数
                int result = OriginalGetPID2(FileTimePtr, MPID, LangId, dwBuildNumber, unk, DPID2);
                Console.WriteLine($"   原始函数返回值: {result}");

                // 解析FileTime指针（增强容错）
                if (FileTimePtr != IntPtr.Zero)
                {
                    Console.WriteLine("\n   📌 FileTime指针解析:");
                    try
                    {
                        // 尝试结构体解析
                        FileTime ft = Marshal.PtrToStructure<FileTime>(FileTimePtr);
                        Console.WriteLine($"      结构体解析 - index: {ft.index}, ActConfigKey: {ft.ActConfigKey ?? "空"}");

                        // 读取原始内存数据（兜底方案）
                        string rawData = Marshal.PtrToStringUni(FileTimePtr, 512)?.Trim('\0') ?? "空";
                        if (!string.IsNullOrEmpty(rawData))
                        {
                            Console.WriteLine($"      原始内存数据: {rawData}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"      解析失败: {ex.Message}");
                        // 读取前100字节的十六进制数据，辅助逆向
                        byte[] buffer = new byte[100];
                        Marshal.Copy(FileTimePtr, buffer, 0, 100);
                        Console.WriteLine($"      前100字节十六进制: {BitConverter.ToString(buffer).Replace("-", " ")}");
                    }
                }
                else
                {
                    Console.WriteLine("   📌 FileTime指针为空");
                }

                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Hook回调异常: {ex.Message}");
                return -1; // 返回错误码，避免调用方崩溃
            }
        }

        /// <summary>
        /// 对应DLL内部的FileTime结构体
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 4)]
        public struct FileTime
        {
            public int index;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string ActConfigKey;
        }
    }
}