using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Reloaded.Hooks;
using Reloaded.Hooks.Definitions;
// 必须导入：FunctionAttribute/Registers 所在命名空间（修复特性缺失的核心）
using Reloaded.Hooks.Definitions.X86;

namespace 密钥检测关键字符串Hook
{
    class Program
    {
        #region 核心配置（保持你的偏移0xA981，统一注释说明）
        private const string TARGET_DLL = "ProductKeyUtilities.dll";          // 目标系统DLL
        private const int GET_PKEYDATA_HOOK_OFFSET = 0xA981;                  // Hook偏移：GetPKeyData+0xA981（对应sub_7BBCA981）
        private const int VALID_HOOK_CALL_COUNT = 2;                          // 有效拦截次数：第三次调用
        private const string TARGET_MATCH_STR = "msft2009";                   // 目标匹配字符串
        private const string TEST_PRODUCT_KEY = "VK7JG-NPHTM-C97JM-9MPGT-3V66T"; // 测试产品密钥
        #endregion

        #region 1. GetPKeyData原生函数委托（StdCall，无修改）
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
            StringBuilder PID
        );
        #endregion

        #region 2. 【核心修复】sub_7BBCA981 Hook委托（添加FunctionAttribute，适配__fastcall）
        // 保留UnmanagedFunctionPointer，适配.NET Marshal封送
        [Function(CallingConventions.Fastcall)]
        private delegate int HookTargetFuncDelegate(int a1, int a2); // 原生：int __fastcall sub_7BBCA981(int a1, int a2)
        #endregion

        #region 全局变量（Hook实例/委托/模块句柄/调用计数器，无修改）
        private static IHook<HookTargetFuncDelegate> _hookTargetFunc; // Hook实例（4.3.3泛型版）
        private static DelegateGetPKeyData _nativeGetPKeyData;        // GetPKeyData原生委托
        private static IntPtr _hModule = IntPtr.Zero;                 // 目标DLL模块句柄
        private static int _hookCallCount = 0;                        // Hook调用计数器（线程安全）
        #endregion

        static void Main(string[] args)
        {
            Console.WriteLine("===== ProductKeyUtilities.dll Hook & Call 开始 =====");
            try
            {
                // 步骤1：加载目标DLL，获取模块句柄
                _hModule = LoadLibrary(TARGET_DLL);
                if (_hModule == IntPtr.Zero)
                {
                    PrintError($"加载{TARGET_DLL}失败", Marshal.GetLastWin32Error());
                    return;
                }
                Console.WriteLine($"✅ 加载{TARGET_DLL}成功，模块基址：0x{_hModule.ToString("X8")}");

                // 步骤2：获取GetPKeyData导出函数地址，封送为C#委托
                IntPtr getPKeyDataAddr = GetProcAddress(_hModule, "GetPKeyData");
                if (getPKeyDataAddr == IntPtr.Zero)
                {
                    PrintError($"获取GetPKeyData地址失败", Marshal.GetLastWin32Error());
                    FreeLibrary(_hModule);
                    return;
                }
                _nativeGetPKeyData = Marshal.GetDelegateForFunctionPointer<DelegateGetPKeyData>(getPKeyDataAddr);
                Console.WriteLine($"✅ 获取GetPKeyData地址成功：0x{getPKeyDataAddr.ToString("X8")}");

                // 步骤3：【核心修复】计算正确Hook地址（GetPKeyData函数地址 + 偏移，而非模块基址+偏移）
                IntPtr hookTargetAddr = IntPtr.Add(_hModule, GET_PKEYDATA_HOOK_OFFSET);
                Console.WriteLine($"✅ 计算Hook目标地址成功sub_7BBCA981 [GetPKeyData+{GET_PKEYDATA_HOOK_OFFSET:X4}]：0x{hookTargetAddr.ToString("X8")}");

                // 步骤4：创建并启用Hook（Reloaded.Hooks 4.3.3标准写法，无修改）
                var hookFactory = new ReloadedHooks();
                _hookTargetFunc = hookFactory.CreateHook<HookTargetFuncDelegate>(
                    HookedGetPKeyData_981,
                    hookTargetAddr.ToInt64()
                );
                _hookTargetFunc.Activate();
                Console.WriteLine($"✅ sub_7BBCA981 Hook启用成功，等待调用触发...\n");

                // 步骤5：调用GetPKeyData原生函数，触发Hook拦截（无修改）
                CallGetPKeyData();

                // 步骤6：卸载Hook，恢复原生函数逻辑（4.3.3版本核心：Disable()）
                _hookTargetFunc?.Disable();
                Console.WriteLine($"\n✅ Hook已禁用，恢复原生sub_7BBCA981执行逻辑");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ 程序执行异常：{ex.Message}\n{ex.StackTrace}");
            }
            finally
            {
                // 最终释放所有非托管资源（优化：避免重复Disable()）
                if (_hookTargetFunc != null)
                {
                    try { _hookTargetFunc.Disable(); } catch { }
                }
                if (_hModule != IntPtr.Zero) FreeLibrary(_hModule);
                Console.WriteLine($"\n✅ 所有非托管资源已释放，程序执行完成");
            }

            Console.WriteLine("\n按任意键退出程序...");
            Console.ReadKey();
        }
        static int count = 0;
        #region Hook拦截函数（匹配2个int参数，无修改）
        private static int HookedGetPKeyData_981(int a1, int a2)
        {
            int currentCount = Interlocked.Increment(ref _hookCallCount);
            Console.WriteLine($"[Hook统计] 第{currentCount}次触发sub_7BBCA981，a1(ECX)={a1}（0x{a1.ToString("X8")}），a2(EDX)={a2}（0x{a2.ToString("X8")}）");

            //if (currentCount == VALID_HOOK_CALL_COUNT)
            //{

            //}
            Console.WriteLine("=====================================================");
            Console.WriteLine($"[🔥 有效调用] 第{count++}次触发sub_7BBCA981，开始提取数据！");

            IntPtr a1Ptr = (IntPtr)a1;
            IntPtr a2Ptr = (IntPtr)a2;

            ExtractUnicodeData(a1Ptr, "a1(ECX)指向的密钥数据");
            ExtractUnicodeData(a2Ptr, "a2(EDX)指向的辅助数据");

            if (a1Ptr != IntPtr.Zero)
            {
                IntPtr a1Offset14 = Marshal.ReadIntPtr(a1Ptr, 0x14);
                ExtractUnicodeData(a1Offset14, "a1+0x14偏移指向的扩展数据");
            }

            bool a1Contain = IsContainTargetStr(a1Ptr, TARGET_MATCH_STR);
            bool a2Contain = IsContainTargetStr(a2Ptr, TARGET_MATCH_STR);
            if (a1Contain)
            {
                Console.WriteLine($"[✅ 匹配成功] a1(ECX)数据包含目标字符串：{TARGET_MATCH_STR}");
            }
            else if (a2Contain)
            {
                Console.WriteLine($"[✅ 匹配成功] a2(EDX)数据包含目标字符串：{TARGET_MATCH_STR}");
            }
            else
            {
                Console.WriteLine($"[⚠️  匹配提示] a1/a2未检测到目标字符串：{TARGET_MATCH_STR}");
            }
            Console.WriteLine("=====================================================\n");

            return _hookTargetFunc.OriginalFunction(a1, a2);
        }
        #endregion

        #region GetPKeyData调用逻辑（无修改，已修复PID=null问题）
        private static void CallGetPKeyData()
        {
            Console.WriteLine("==================== 开始调用GetPKeyData ====================");
            string productKey = TEST_PRODUCT_KEY;
            string configPath = Path.Combine(Environment.CurrentDirectory, "pkconfig_winNext.xrm-ms");
            StringBuilder pidSb = new StringBuilder(512);
            string iid = null, description = null, channel = null, subType = null;

            if (!File.Exists(configPath))
            {
                Console.WriteLine($"❌ 配置文件不存在：{configPath}");
                Console.WriteLine($"提示：请将pkconfig_winNext.xrm-ms放在程序运行目录下");
                return;
            }

            try
            {
                int retCode = _nativeGetPKeyData(
                    productKey, configPath, null, null, IntPtr.Zero, IntPtr.Zero,
                    out iid, out description, out channel, out subType, pidSb
                );

                if (retCode == 0)
                {
                    Console.WriteLine("✅ GetPKeyData调用成功，结构化数据如下：");
                    Console.WriteLine($"产品密钥：{productKey}");
                    Console.WriteLine($"IID唯一标识：{iid ?? "空"}");
                    Console.WriteLine($"密钥描述：{description ?? "空"}");
                    Console.WriteLine($"密钥通道：{channel ?? "空"}");
                    Console.WriteLine($"密钥子类型：{subType ?? "空"}");
                    Console.WriteLine($"PID标识码：{pidSb.ToString() ?? "空"}");
                }
                else
                {
                    PrintError($"GetPKeyData调用失败，返回码", retCode);
                    PrintError($"系统底层错误码", Marshal.GetLastWin32Error());
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ 调用GetPKeyData异常：{ex.Message}");
            }
            finally
            {
                FreeNativeOutString(iid);
                FreeNativeOutString(description);
                FreeNativeOutString(channel);
                FreeNativeOutString(subType);
            }
            Console.WriteLine("===============================================================");
        }
        #endregion

        #region 辅助方法（无修改）
        private static void ExtractUnicodeData(IntPtr ptr, string desc)
        {
            // 1. 空指针直接返回
            if (ptr == IntPtr.Zero)
            {
                Console.WriteLine($"{desc}：指针为空（IntPtr.Zero）");
                return;
            }

            // 2. 32位地址范围校验
            if ((long)ptr > 0x7FFFFFFF || (long)ptr < 0x00010000)
            {
                Console.WriteLine($"{desc}：指针地址无效（0x{ptr.ToString("X8")}），不在32位有效内存范围");
                return;
            }

            // 3. 尝试用系统API探测内存是否可读
            if (!IsMemoryReadable(ptr, 2)) // 先探测2字节（1个Unicode字符）
            {
                Console.WriteLine($"{desc}：内存不可读（0x{ptr.ToString("X8")}），跳过读取");
                return;
            }

            // 4. 安全读取字符串（仅在内存可读时执行）
            string unicodeStr = null;
            try
            {
                unicodeStr = Marshal.PtrToStringUni(ptr, 512);
            }
            catch
            {
                Console.WriteLine($"{desc}：读取失败，可能为非Unicode数据");
                return;
            }

            // 5. 处理结果
            if (string.IsNullOrEmpty(unicodeStr))
            {
                Console.WriteLine($"{desc}：空字符串或非Unicode数据");
            }
            else
            {
                string showStr = unicodeStr.Substring(0, Math.Min(unicodeStr.Length, 256));
                Console.WriteLine($"{desc}：{showStr}");
                Console.WriteLine($"{desc}内存地址：0x{ptr.ToString("X8")}");
            }
        }

        // 辅助函数：用系统API探测内存是否可读
        [DllImport("kernel32.dll")]
        private static extern bool IsBadReadPtr(IntPtr lp, uint ucb);
        private static bool IsMemoryReadable(IntPtr ptr, int size)
        {
            return !IsBadReadPtr(ptr, (uint)size);
        }

        private static bool IsContainTargetStr(IntPtr ptr, string target)
        {
            if (ptr == IntPtr.Zero || string.IsNullOrEmpty(target)) return false;
            try
            {
                string unicodeStr = Marshal.PtrToStringUni(ptr);
                return unicodeStr != null && unicodeStr.Contains(target);
            }
            catch
            {
                return false;
            }
        }
        private static readonly string[] TARGET_KEYS =
        {
            "msft2009",
            "msft2005"
        };


        private static void FreeNativeOutString(string str)
        {
            if (!string.IsNullOrEmpty(str))
            {
                try
                {
                    IntPtr strPtr = Marshal.StringToHGlobalUni(str);
                    Marshal.FreeCoTaskMem(strPtr);
                }
                catch { }
            }
        }

        private static void PrintError(string msg, int errorCode)
        {
            Console.WriteLine($"❌ {msg}：0x{errorCode:X8}（十进制：{errorCode}）");
        }
        #endregion

        #region Kernel32.dll API导入（无修改）
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr hModule);
        #endregion
    }
}