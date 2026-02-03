using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Reloaded.Hooks;
using Reloaded.Hooks.Definitions;

namespace ProductKeyHookAndCall
{
    class Program
    {
        #region 核心配置（可根据实际需求修改）
        private const string TARGET_DLL = "ProductKeyUtilities.dll";          // 目标系统DLL
        private const int GET_PKEYDATA_HOOK_OFFSET = 0x981;                   // Hook偏移：GetPKeyData+981
        private const int VALID_HOOK_CALL_COUNT = 3;                          // 有效拦截次数：第三次调用
        private const string TARGET_MATCH_STR = "msft2009";                   // 目标匹配字符串
        private const string TEST_PRODUCT_KEY = "VK7JG-NPHTM-C97JM-9MPGT-3V66T"; // 测试产品密钥
        #endregion

        #region 1. GetPKeyData原生函数委托（StdCall，与原生函数完全匹配）
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

        #region 2. GetPKeyData+981 Hook目标委托（FastCall，ECX=A1 EDX=A2，适配原生调用）
        [UnmanagedFunctionPointer(CallingConvention.FastCall, CharSet = CharSet.Unicode)]
        private delegate int HookTargetFuncDelegate(IntPtr a1, IntPtr a2, IntPtr a3);
        #endregion

        #region 全局变量（Hook实例/委托/模块句柄/调用计数器）
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
                    PrintError($"获取GetPKeyData函数地址失败", Marshal.GetLastWin32Error());
                    FreeLibrary(_hModule);
                    return;
                }
                _nativeGetPKeyData = Marshal.GetDelegateForFunctionPointer<DelegateGetPKeyData>(getPKeyDataAddr);
                Console.WriteLine($"✅ 获取GetPKeyData地址成功：0x{getPKeyDataAddr.ToString("X8")}");

                // 步骤3：计算GetPKeyData+981绝对Hook地址
                IntPtr hookTargetAddr = IntPtr.Add(getPKeyDataAddr, GET_PKEYDATA_HOOK_OFFSET);
                Console.WriteLine($"✅ 计算Hook目标地址成功 [GetPKeyData+{GET_PKEYDATA_HOOK_OFFSET:X3}]：0x{hookTargetAddr.ToString("X8")}");

                // 步骤4：创建并启用Hook（Reloaded.Hooks 4.3.3标准写法）
                var hookFactory = new ReloadedHooks();
                _hookTargetFunc = hookFactory.CreateHook<HookTargetFuncDelegate>(HookedGetPKeyData_981, hookTargetAddr.ToInt64());
                _hookTargetFunc.Activate(); // 初始化+启用Hook（仅调用一次）
                Console.WriteLine($"✅ GetPKeyData+981 Hook启用成功，等待调用触发...\n");

                // 步骤5：调用GetPKeyData原生函数，触发Hook拦截
                CallGetPKeyData();

                // 步骤6：卸载Hook，恢复原生函数逻辑（4.3.3版本核心：Disable()）
                _hookTargetFunc?.Disable();
                Console.WriteLine($"\n✅ Hook已禁用，恢复原生函数执行逻辑");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ 程序执行异常：{ex.Message}\n{ex.StackTrace}");
            }
            finally
            {
                // 最终释放所有非托管资源
                if (_hookTargetFunc != null) _hookTargetFunc.Disable();
                if (_hModule != IntPtr.Zero) FreeLibrary(_hModule);
                Console.WriteLine($"\n✅ 所有非托管资源已释放，程序执行完成");
            }

            Console.WriteLine("\n按任意键退出程序...");
            Console.ReadKey();
        }

        #region 核心：GetPKeyData+981 Hook拦截函数（第三次调用提取数据）
        /// <summary>
        /// Hook拦截后的执行函数，与原生FastCall约定一致
        /// a1=ECX，a2=EDX，a3=栈传参数（可根据逆向结果调整参数数量/类型）
        /// </summary>
        private static int HookedGetPKeyData_981(IntPtr a1, IntPtr a2, IntPtr a3)
        {
            // 线程安全自增计数器，避免多线程计数错乱
            int currentCount = Interlocked.Increment(ref _hookCallCount);
            Console.WriteLine($"[Hook统计] 第{currentCount}次触发GetPKeyData+981，ECX(a1)=0x{a1.ToString("X8")}");

            // 仅处理第三次有效调用，提取核心数据
            if (currentCount == VALID_HOOK_CALL_COUNT)
            {
                Console.WriteLine("=====================================================");
                Console.WriteLine($"[🔥 有效调用] 第三次触发，开始提取密钥相关数据！");
                // 提取ECX(a1)直接指向的宽字符数据
                ExtractUnicodeData(a1, "ECX(a1)直接指向的原始数据");
                // 提取a1+0x14偏移指向的数据（适配常见逆向场景，可根据实际修改偏移）
                IntPtr offset14Ptr = Marshal.ReadIntPtr(a1, 0x14); // x86：4字节指针，偏移0x14
                ExtractUnicodeData(offset14Ptr, "a1+0x14偏移指向的密钥数据");
                // 验证是否包含目标字符串
                if (IsContainTargetStr(a1, TARGET_MATCH_STR))
                {
                    Console.WriteLine($"[✅ 匹配成功] ECX数据包含目标字符串：{TARGET_MATCH_STR}");
                }
                else if (IsContainTargetStr(offset14Ptr, TARGET_MATCH_STR))
                {
                    Console.WriteLine($"[✅ 匹配成功] a1+0x14数据包含目标字符串：{TARGET_MATCH_STR}");
                }
                else
                {
                    Console.WriteLine($"[⚠️  匹配提示] 未检测到目标字符串：{TARGET_MATCH_STR}");
                }
                Console.WriteLine("=====================================================\n");
            }

            // 必须调用原生函数，保证GetPKeyData原有业务逻辑不中断
            return _hookTargetFunc.OriginalFunction(a1, a2, a3);
        }
        #endregion

        #region 业务层：调用GetPKeyData原生函数，获取结构化密钥数据
        private static void CallGetPKeyData()
        {
            Console.WriteLine("==================== 开始调用GetPKeyData ====================");
            // 初始化参数
            string productKey = TEST_PRODUCT_KEY;
            // 安全拼接配置文件路径（自动处理目录分隔符，避免无效路径）
            string configPath = Path.Combine(Environment.CurrentDirectory, "pkconfig_winNext.xrm-ms");
            // 关键：初始化PID输出缓冲区，指定足够容量（避免崩溃/数据截断）
            StringBuilder pidSb = new StringBuilder(512);
            // out参数无需提前赋值，C#自动处理
            string iid = null, description = null, channel = null, subType = null;

            // 前置检查：配置文件是否存在
            if (!File.Exists(configPath))
            {
                Console.WriteLine($"❌ 配置文件不存在：{configPath}");
                Console.WriteLine($"提示：请将pkconfig_winNext.xrm-ms放在程序运行目录下");
                return;
            }

            try
            {
                // 调用原生GetPKeyData函数（会触发GetPKeyData+981 Hook）
                int retCode = _nativeGetPKeyData(
                    productKey,       // 产品密钥
                    configPath,       // 配置文件路径
                    null,             // MPCID：无则传null
                    null,             // 密钥算法：无则传null
                    IntPtr.Zero,      // OemId：无需处理传IntPtr.Zero
                    IntPtr.Zero,      // OtherId：无需处理传IntPtr.Zero
                    out iid,          // 输出：密钥唯一IID
                    out description,  // 输出：密钥描述
                    out channel,      // 输出：密钥通道（零售/批量等）
                    out subType,      // 输出：密钥子类型
                    pidSb             // 输出：PID（已初始化缓冲区）
                );

                // 处理调用结果
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
                // 必须释放：原生函数为out string分配的非托管内存（避免内存泄漏）
                FreeNativeOutString(iid);
                FreeNativeOutString(description);
                FreeNativeOutString(channel);
                FreeNativeOutString(subType);
            }
            Console.WriteLine("===============================================================");
        }
        #endregion

        #region 辅助方法：宽字符解析/字符串匹配/内存释放/错误打印
        /// <summary>
        /// 从指针解析Unicode（宽字符）字符串并打印（适配Windows wchar_t*）
        /// </summary>
        private static void ExtractUnicodeData(IntPtr ptr, string desc)
        {
            if (ptr == IntPtr.Zero)
            {
                Console.WriteLine($"{desc}：指针为空（IntPtr.Zero）");
                return;
            }
            try
            {
                string unicodeStr = Marshal.PtrToStringUni(ptr);
                if (string.IsNullOrEmpty(unicodeStr))
                {
                    Console.WriteLine($"{desc}：空字符串");
                    return;
                }
                // 限制显示长度，避免超长字符串刷屏
                string showStr = unicodeStr.Substring(0, Math.Min(unicodeStr.Length, 256));
                Console.WriteLine($"{desc}：{showStr}");
                Console.WriteLine($"{desc}内存地址：0x{ptr.ToString("X8")}");
            }
            catch
            {
                Console.WriteLine($"{desc}：解析失败（非有效宽字符指针）");
            }
        }

        /// <summary>
        /// 判断指针指向的宽字符字符串是否包含目标子串
        /// </summary>
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

        /// <summary>
        /// 释放原生GetPKeyData为out string分配的非托管内存（必做！）
        /// </summary>
        private static void FreeNativeOutString(string str)
        {
            if (!string.IsNullOrEmpty(str))
            {
                try
                {
                    IntPtr strPtr = Marshal.StringToHGlobalUni(str);
                    Marshal.FreeCoTaskMem(strPtr);
                }
                catch { /* 忽略释放异常，不影响主流程 */ }
            }
        }

        /// <summary>
        /// 格式化打印错误信息
        /// </summary>
        private static void PrintError(string msg, int errorCode)
        {
            Console.WriteLine($"❌ {msg}：0x{errorCode:X8}（十进制：{errorCode}）");
        }
        #endregion

        #region 导入Kernel32.dll核心API（模块加载/函数地址获取/资源释放）
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr hModule);
        #endregion
    }
}