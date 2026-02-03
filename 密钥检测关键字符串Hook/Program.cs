using Reloaded.Hooks;
using Reloaded.Hooks.Definitions;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using 密钥检测关键字符串Hook;

namespace 密钥检测关键字符串Hook
{
    class Program
    {
        #region 核心配置区（根据你的逆向结果修改，已适配你的场景）
        private const string TARGET_DLL = "ProductKeyUtilities.dll"; // 目标模块
        private const int GET_PKEYDATA_HOOK_OFFSET = 0x981;          // GetPKeyData+981 偏移
        private const int VALID_HOOK_CALL_COUNT = 3;                 // 有效Hook调用次数：第三次
        private const string TARGET_MATCH_STR = "msft2009";          // 目标匹配字符串
        // 测试用产品密钥和配置文件路径（替换为你的实际值）
        private const string TEST_PRODUCT_KEY = "VK7JG-NPHTM-C97JM-9MPGT-3V66T";
        string pkeyconfigxml = System.Environment.CurrentDirectory + "\\pkconfig_winNext.xrm-ms";
        #endregion

        #region 1. 你定义的GetPKeyData委托（原封不动复用）
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

        #region 2. Hook相关全局变量（委托/实例/计数器）
        // GetPKeyData+981指向的原生函数委托（__fastcall：ECX=a1, EDX=a2，适配原生调用）
        [UnmanagedFunctionPointer(CallingConvention.FastCall, CharSet = CharSet.Unicode)]
        private delegate int HookTargetFuncDelegate(IntPtr a1, IntPtr a2, IntPtr a3);
        // Hook实例（用于激活/卸载，恢复原生函数）
        private static IHook _hookTargetFunc;
        // Hook调用次数计数器（Interlocked保证线程安全，避免多线程计数错乱）
        private static int _hookCallCount = 0;
        // GetPKeyData原生函数委托（用于后续调用）
        private static DelegateGetPKeyData _nativeGetPKeyData;
        // 目标模块句柄（全局保留，最后统一释放）
        private static IntPtr _hModule = IntPtr.Zero;
        #endregion

        static void Main(string[] args)
        {
            try
            {
                // 步骤1：加载目标模块，获取基址
                _hModule = LoadLibrary(TARGET_DLL);
                if (_hModule == IntPtr.Zero)
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine($"❌ 加载{TARGET_DLL}失败，错误码：0x{errorCode:X8}");
                    return;
                }
                Console.WriteLine($"✅ 加载{TARGET_DLL}成功，模块基址：0x{_hModule.ToString("X8")}");

                // 步骤2：获取GetPKeyData导出函数地址，封送为C#委托
                IntPtr getPKeyDataAddr = GetProcAddress(_hModule, "GetPKeyData");
                if (getPKeyDataAddr == IntPtr.Zero)
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine($"❌ 获取GetPKeyData地址失败，错误码：0x{errorCode:X8}");
                    FreeLibrary(_hModule);
                    return;
                }
                _nativeGetPKeyData = Marshal.GetDelegateForFunctionPointer<DelegateGetPKeyData>(getPKeyDataAddr);
                Console.WriteLine($"✅ 获取GetPKeyData导出地址成功：0x{getPKeyDataAddr.ToString("X8")}");

                // 步骤3：计算GetPKeyData+981绝对地址（核心Hook目标）
                IntPtr hookTargetAddr = IntPtr.Add(getPKeyDataAddr, GET_PKEYDATA_HOOK_OFFSET);
                Console.WriteLine($"✅ 计算Hook目标地址成功 [GetPKeyData+{GET_PKEYDATA_HOOK_OFFSET:X3}]：0x{hookTargetAddr.ToString("X8")}");

                // 步骤4：初始化并激活Hook（Reloaded.Hooks自动处理内存保护/指令跳板）
                var hookFactory = new ReloadedHooks();
                _hookTargetFunc = hookFactory.CreateHook<HookTargetFuncDelegate>(HookedGetPKeyData_981, hookTargetAddr.ToInt64()).Activate();
                Console.WriteLine($"✅ GetPKeyData+981 Hook安装成功，等待调用触发...\n");

                // 步骤5：调用GetPKeyData委托，触发Hook执行
                CallGetPKeyData();

                // 步骤6：卸载Hook，恢复原生函数
                
                _hookTargetFunc.Disable();
                Console.WriteLine($"\n✅ Hook已卸载，恢复原生函数逻辑");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ 程序执行异常：{ex.Message}\n{ex.StackTrace}");
            }
            finally
            {
                // 最终释放模块句柄，避免非托管资源泄漏
                if (_hModule != IntPtr.Zero)
                {
                    FreeLibrary(_hModule);
                    Console.WriteLine($"✅ 释放{TARGET_DLL}模块句柄成功");
                }
            }

            Console.WriteLine("\n按任意键退出程序...");
            Console.ReadKey();
        }

        #region 核心：GetPKeyData+981 Hook拦截函数（第三次调用提取数据）
        /// <summary>
        /// Hook拦截后的执行函数，与原生函数签名一致（__fastcall）
        /// a1=ECX，a2=EDX，a3=栈传参数（按需调整参数数量，不影响核心调用）
        /// </summary>
        private static int HookedGetPKeyData_981(IntPtr a1, IntPtr a2, IntPtr a3)
        {
            // 线程安全自增计数器，避免多线程调用计数错乱
            int currentCount = Interlocked.Increment(ref _hookCallCount);
            Console.WriteLine($"[Hook调用统计] 第{currentCount}次触发GetPKeyData+981，ECX(a1)=0x{a1.ToString("X8")}");

            // 仅处理第三次有效调用，提取核心数据
            if (currentCount == VALID_HOOK_CALL_COUNT)
            {
                Console.WriteLine("=====================================================");
                Console.WriteLine($"[🔥 有效调用触发] 第三次GetPKeyData+981调用，开始提取数据！");
                // 提取ECX(a1)直接指向的宽字符数据（核心：msft2009相关）
                ExtractUnicodeData(a1, "ECX(a1)直接指向的原始数据");
                // 可选：若数据在a1+0x14偏移（你之前的逆向场景），解耦提取
                IntPtr offset14Ptr = Marshal.ReadIntPtr(a1, 0x14); // x86：4字节指针，偏移0x14
                ExtractUnicodeData(offset14Ptr, "a1+0x14偏移指向的密钥数据");
                // 验证数据是否包含目标字符串msft2009
                if (IsContainTargetStr(a1, TARGET_MATCH_STR))
                {
                    Console.WriteLine($"[✅ 匹配成功] 数据包含目标字符串：{TARGET_MATCH_STR}");
                }
                else if (IsContainTargetStr(offset14Ptr, TARGET_MATCH_STR))
                {
                    Console.WriteLine($"[✅ 匹配成功] a1+0x14数据包含目标字符串：{TARGET_MATCH_STR}");
                }
                else
                {
                    Console.WriteLine($"[⚠️  匹配失败] 未找到目标字符串：{TARGET_MATCH_STR}");
                }
                Console.WriteLine("=====================================================\n");
            }

            // 必须调用原生函数，保证GetPKeyData原有逻辑不中断（否则会导致委托调用失败/数据异常）
            return _hookTargetFunc.OriginalFunction<HookTargetFuncDelegate>()(a1, a2, a3);
        }
        #endregion

        #region 业务层：调用GetPKeyData委托，获取结构化密钥数据
        private static void CallGetPKeyData()
        {
            Console.WriteLine("==================== 开始调用GetPKeyData ====================");
            // 1. 初始化参数（替换为你的实际配置文件路径）
            string productKey = TEST_PRODUCT_KEY;
            string pkeyConfigPath = Path.Combine(Environment.CurrentDirectory, "pkconfig_winNext.xrm-ms");
            // 关键：PID输出缓冲区必须初始化容量，避免崩溃/数据截断（建议256+）
            StringBuilder pidSb = new StringBuilder(512);
            // out参数无需提前赋值，C#自动处理
            string iid = null, description = null, channel = null, subType = null;

            // 2. 检查配置文件是否存在（避免调用失败）
            if (!File.Exists(pkeyConfigPath))
            {
                Console.WriteLine($"❌ 配置文件不存在：{pkeyConfigPath}");
                return;
            }

            try
            {
                // 3. 调用原生GetPKeyData函数（会触发GetPKeyData+981 Hook）
                int retCode = _nativeGetPKeyData(
                    productKey,       // 产品密钥
                    pkeyConfigPath,   // 配置文件路径
                    null,             // MPCID：无则传null
                    null,             // 密钥算法：无则传null
                    IntPtr.Zero,      // OemId：无需处理传IntPtr.Zero
                    IntPtr.Zero,      // OtherId：无需处理传IntPtr.Zero
                    out iid,          // 输出：IID唯一标识
                    out description,  // 输出：密钥描述
                    out channel,      // 输出：密钥通道（零售/批量等）
                    out subType,      // 输出：密钥子类型
                    pidSb             // 输出：PID缓冲区（已初始化）
                );

                // 4. 处理调用结果
                if (retCode == 0)
                {
                    Console.WriteLine("✅ GetPKeyData调用成功，结构化数据如下：");
                    Console.WriteLine($"产品密钥：{productKey}");
                    Console.WriteLine($"IID：{iid ?? "空"}");
                    Console.WriteLine($"密钥描述：{description ?? "空"}");
                    Console.WriteLine($"密钥通道：{channel ?? "空"}");
                    Console.WriteLine($"密钥子类型：{subType ?? "空"}");
                    Console.WriteLine($"PID：{pidSb.ToString() ?? "空"}");
                }
                else
                {
                    Console.WriteLine($"❌ GetPKeyData调用失败，返回码：0x{retCode:X8}");
                    int win32Error = Marshal.GetLastWin32Error();
                    Console.WriteLine($"系统错误码：0x{win32Error:X8}（可通过Win32Error工具解析）");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ GetPKeyData调用异常：{ex.Message}");
            }
            finally
            {
                // 关键：释放原生分配的out string内存，避免非托管内存泄漏
                FreeNativeOutString(iid);
                FreeNativeOutString(description);
                FreeNativeOutString(channel);
                FreeNativeOutString(subType);
            }
            Console.WriteLine("===============================================================");
        }
        #endregion

        #region 辅助方法：宽字符数据提取/匹配 + 非托管内存释放
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
                // 解析宽字符字符串，自动截断到空字符
                string unicodeStr = Marshal.PtrToStringUni(ptr);
                if (string.IsNullOrEmpty(unicodeStr))
                {
                    Console.WriteLine($"{desc}：空字符串");
                    return;
                }
                // 限制显示长度（避免超长字符串刷屏，可调整）
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
        /// 判断指针指向的宽字符是否包含目标字符串
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
        /// 释放原生GetPKeyData分配的out string内存（必做！避免泄漏）
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
                catch { /* 忽略释放异常，避免影响主流程 */ }
            }
        }
        #endregion

        #region 导入kernel32.dll核心API（模块加载/释放/函数地址获取）
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr hModule);
        #endregion
    }
}