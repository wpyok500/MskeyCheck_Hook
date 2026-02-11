using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Reloaded.Hooks;
using Reloaded.Hooks.Definitions;
using Reloaded.Hooks.Definitions.Enums;

// 必须导入：FunctionAttribute/Registers 所在命名空间（修复特性缺失的核心）
using Reloaded.Hooks.Definitions.X86;

namespace 密钥检测关键字符串Hook
{
    class Program
    {
        // 核心配置（保持你的偏移0x16AB0，统一注释说明）
        private const string TARGET_DLL = "ProductKeyUtilities.dll";          // 目标系统DLL
        private const int HOOK_OFFSET = 0x16AB0;                  // Hook偏移：0x16AB0     
        private const string TEST_PRODUCT_KEY = "VK7JG-NPHTM-C97JM-9MPGT-3V66T"; // 测试产品密钥 VK7JG-NPHTM-C97JM-9MPGT-3V66T
        private const string configPath = "pkconfig_winNext.xrm-ms";

        #region 定义委托
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

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate void OnESIDelegate(IntPtr esi);
        #endregion

        #region 全局变量（Hook实例/委托/模块句柄/调用计数器，无修改）
        private static DelegateGetPKeyData _nativeGetPKeyData;

        private static IAsmHook _asmHook;
        private static ReloadedHooks _hooksInstance;
        private static IntPtr _callbackPtr;
        static OnESIDelegate _onEsi = OnESI;
        static IntPtr _onEsiPtr;

        private static IntPtr _hModule = IntPtr.Zero;                 // 目标DLL模块句柄
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
                    Console.WriteLine($"加载{TARGET_DLL}失败", FreeLibrary(_hModule));
                    return;
                }
                Console.WriteLine($"✅ 加载{TARGET_DLL}成功，模块基址：0x{_hModule.ToString("X8")}");

                _onEsiPtr = Marshal.GetFunctionPointerForDelegate<OnESIDelegate>(_onEsi);
                Console.WriteLine($"✅ 获取GetPKeyData地址成功：0x{_onEsiPtr.ToString("X8")}");

                IntPtr hookTargetAddr = IntPtr.Add(_hModule, HOOK_OFFSET);
                Console.WriteLine($"✅ 计算Hook目标地址成功 ：0x{hookTargetAddr.ToString("X8")}");

                InstallAsmHook(hookTargetAddr.ToInt64());
                Console.WriteLine($"✅ Hook启用成功，等待调用触发...\n");

                CallGetPKeyData();

                Console.WriteLine($"\n✅ Hook已禁用，恢复原生sub_7BBCA981执行逻辑");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ 程序执行异常：{ex.Message}\n{ex.StackTrace}");
            }
            finally
            {

                if (_hModule != IntPtr.Zero) FreeLibrary(_hModule);
                Console.WriteLine($"\n✅ 所有非托管资源已释放，程序执行完成");
            }

            Console.WriteLine("\n按任意键退出程序...");
            Console.ReadKey();
        }
        private static void InstallAsmHook(long hookAddress)
        {
            // asm 写法一
            // Reloaded.Hooks 在 x86 下会自动处理 5 字节跳转
            // 我们只需要保护现场 -> 传参调用 -> 恢复现场
            string[] asm =
            {
                "use32",                 // 明确告诉汇编器这是 32 位代码

                // --- 1. 环境保护 ---
                "pushad",                // 保存 EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI
                "pushfd",                // 保存标志位

                // --- 2. 传参并调用 C# ---
                "push esi",              // 此时 ESI 是已经赋值好的 Key 字符串地址
                $"mov eax, {_onEsiPtr.ToInt32()}",
                "call eax",
                "add esp, 4",            // 平衡 push esi 产生的 4 字节栈空间

                // --- 3. 环境恢复 ---
                "popfd",
                "popad"

                // 注意：这里不需要手动写 and dword ptr [ebp-20], 0
                // 因为我们将 Behaviour 设置为 ExecuteFirst，Reloaded 会自动在我们的代码后执行原指令
            };

            // asm 写法二
            //string[] asm =
            //{
            //    "use32",

            //    // 1. 保护寄存器 (注意顺序：先 push 的后 pop)
            //    "push eax",
            //    "push ecx",
            //    "push edx",
            //    "push ebx",
            //    "push ebp",
            //    "push esi",
            //    "push edi",
            //    "pushfd",               // 额外保护一下标志位，防止 C# 逻辑干扰跳转指令

            //    // 2. 执行原始指令 (手动补偿)
            //    "add dword [ebp - 20h], 0",  //"and dword ptr [ebp - 20h], 0", 不能有ptr会报fasm错误 ,更推荐"mov dword [ebp - 20h], 0"

            //    // 3. 调用 C# 函数 (栈传参模式)
            //    "push esi",             // 把 esi 压入栈，作为 C# 函数的第一个参数
            //    $"mov eax, {_onEsiPtr.ToInt32():X8}h", // 32位环境用 ToInt32,需要加前缀0x 否则报错
            //    "call eax",
            //    "add esp, 4",           // 重要：如果是 Cdecl 调用约定，必须手动平栈

            //    // 4. 恢复现场
            //    "popfd",
            //    "pop edi",
            //    "pop esi",
            //    "pop ebp",
            //    "pop ebx",
            //    "pop edx",
            //    "pop ecx",
            //    "pop eax"

            //    // 注意：不要手动写 jmp 0x7B106AB4。
            //    // Reloaded.Hooks 会在 asm 数组执行完后，自动帮你跳回正确的地址。
            //};

            _hooksInstance = new ReloadedHooks();

            _asmHook = _hooksInstance.CreateAsmHook(
                asm,
                hookAddress,
                AsmHookBehaviour.ExecuteFirst // 先执行我们的 push/call，再执行原程序的 and [ebp-20], 0
            ).Activate();

            Console.WriteLine($"[+] Hook 成功激活于: 0x{hookAddress:X}");
        }
        #region Hook拦截函数
        private static void OnESI(IntPtr esi)
        {
            // 1️⃣ 永远判空
            if (esi == IntPtr.Zero)
                return;

            // 2️⃣ 只读，不修改
            string s = Marshal.PtrToStringUni(esi);

            // 3️⃣ 逻辑尽量轻
            if (s != null && s.StartsWith("msft2009:"))
            {
                Console.WriteLine($"[Esi] {s}");
            }
        }

        #endregion

        #region GetPKeyData调用逻辑（无修改，已修复PID=null问题）
        private static void CallGetPKeyData()
        {
            Console.WriteLine("==================== 开始调用GetPKeyData ====================");
            IntPtr getPKeyDataAddr = GetProcAddress(_hModule, "GetPKeyData");
            if (getPKeyDataAddr == IntPtr.Zero)
            {
                Console.WriteLine($"获取GetPKeyData地址失败");
                FreeLibrary(_hModule);
                return;
            }
            _nativeGetPKeyData = Marshal.GetDelegateForFunctionPointer<DelegateGetPKeyData>(getPKeyDataAddr);
            Console.WriteLine($"✅ 获取GetPKeyData地址成功：0x{getPKeyDataAddr.ToString("X8")}");
            string productKey = TEST_PRODUCT_KEY;

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
                    Console.WriteLine($"GetPKeyData调用失败，返回码{retCode}");
                    Console.WriteLine($"系统底层错误码{Marshal.GetLastWin32Error()}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ 调用GetPKeyData异常：{ex.Message}");
            }
            finally
            {
                FreeLibrary(getPKeyDataAddr);
            }
            Console.WriteLine("===============================================================");
        }
        #endregion

        #region 辅助方法（无修改）

        // 辅助函数：用系统API探测内存是否可读
        [DllImport("kernel32.dll")]
        private static extern bool IsBadReadPtr(IntPtr lp, uint ucb);

        
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