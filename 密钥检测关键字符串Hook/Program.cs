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

        #region 2. 
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate void OnESIDelegate(IntPtr esi);
        #endregion

        #region 全局变量（Hook实例/委托/模块句柄/调用计数器，无修改）
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

                // 步骤2：获取GetPKeyData导出函数地址，封送为C#委托
                
                //
                _onEsiPtr = Marshal.GetFunctionPointerForDelegate<OnESIDelegate>(_onEsi);
                Console.WriteLine($"✅ 获取GetPKeyData地址成功：0x{getPKeyDataAddr.ToString("X8")}");

                // 步骤3：【核心修复】计算正确Hook地址（GetPKeyData函数地址 + 偏移，而非模块基址+偏移）
                IntPtr hookTargetAddr = IntPtr.Add(_hModule, HOOK_OFFSET);
                Console.WriteLine($"✅ 计算Hook目标地址成功 ：0x{hookTargetAddr.ToString("X8")}");
                Console.ReadKey();
                //步骤4：创建并启用Hook
                InstallAsmHook(hookTargetAddr.ToInt64());
                Console.WriteLine($"✅ Hook启用成功，等待调用触发...\n");

                // 步骤5：调用GetPKeyData原生函数，触发Hook拦截（无修改）
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
            /*
             * 栈布局说明：
             * - push 8 个非易失寄存器 = 64 字节
             * - sub rsp, 20h         = shadow space
             *
             * 原始 RSP = 当前 rsp + 20h + 8*8
             */
            // 计算需要保护的所有易失寄存器
            // 注意：x64 下除了 RCX, RDX, R8, R9, 还包括 RAX, R10, R11 和 XMM0-XMM5
            string[] asm =
            {
                // --- 1. 环境保护 ---
                "pushad",                // 保存所有通用寄存器 (EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI)
                "pushfd",                // 保存标志寄存器 (EFLAGS)

                // --- 2. 传递参数并调用 C# ---
                // 此时 ESI 指向 Key 字符串：L"msft2009:..."
                "push esi",              // 将 ESI 压栈作为第一个参数
                $"mov eax, {_onEsiPtr.ToInt32()}",
                "call eax",              // 调用托管代码
                "add esp, 4",            // 平衡栈 (cdecl 约定)

                // --- 3. 环境恢复 ---
                "popfd",                 // 还原标志位
                "popad",                 // 还原寄存器

                // --- 4. 修复指令（必须补足被覆盖的字节） ---
                // 7BD16AB0 处指令: 83 65 E0 00 (4字节)
                // 7BD16AB4 处指令: 89 42 08    (3字节)
                // 如果 Hook 占用 5 字节，则这两条指令都需要在此时完整补回
                "and dword ptr [ebp-0x20], 0",
                "mov [edx+0x08], eax"
            };
            _hooksInstance = new ReloadedHooks();

            _asmHook = _hooksInstance.CreateAsmHook(
                asm,
                hookAddress,
                AsmHookBehaviour.ExecuteFirst
            ).Activate();

            Console.WriteLine("[+] AsmHook 激活成功");
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
                Console.WriteLine($"[RDI] {s}");
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