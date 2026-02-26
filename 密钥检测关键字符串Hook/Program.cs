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
        [DllImport("kernel32.dll")]
        internal static extern bool RtlZeroMemory(IntPtr destination, int length);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int DelegatePidGenX(string ProductKey, string PkeyPath, string MSPID, IntPtr oemId, IntPtr ProductID, IntPtr DigitalProductID, IntPtr DigitalProductID4);
        [DllImport("pidgenx.dll", EntryPoint = "PidGenX", CharSet = CharSet.Auto)]
        private static extern int PidGenX(string ProductKey, string PkeyPath, string MSPID, string oemId, IntPtr ProductID, IntPtr DigitalProductID, IntPtr DigitalProductID4);


        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] //若是64位dll,用winapi
        delegate void OnESIDelegate(IntPtr esi);
        #endregion

        #region 全局变量（Hook实例/委托/模块句柄/调用计数器，无修改）
        private static DelegatePidGenX _nativePidGenX;

        private static IAsmHook _asmHook;
        private static ReloadedHooks _hooksInstance;
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
                Console.WriteLine($"✅ 获取回调函数地址成功：0x{_onEsiPtr.ToString("X8")}");

                IntPtr hookTargetAddr = IntPtr.Add(_hModule, HOOK_OFFSET);
                Console.WriteLine($"✅ 计算Hook目标地址成功 ：0x{hookTargetAddr.ToString("X8")}");

                InstallAsmHook(hookTargetAddr.ToInt64());
                Console.WriteLine($"✅ Hook启用成功，等待调用触发...\n");

                CallPidGenX();
                _asmHook?.Disable();
                Console.WriteLine($"\n✅ Hook已禁用，恢复原生执行逻辑");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ 程序执行异常：{ex.Message}\n{ex.StackTrace}");
            }
            finally
            {
                // 释放Hook资源
                _asmHook?.Disable();

                // 释放DLL模块
                if (_hModule != IntPtr.Zero)
                {
                    FreeLibrary(_hModule);
                    _hModule = IntPtr.Zero;
                }
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
            if (esi == IntPtr.Zero || IsBadReadPtr(esi, 1))
                return;

            // 2️⃣ 只读，不修改
            string s = Marshal.PtrToStringUni(esi);

            // 3️⃣ 逻辑尽量轻
            if (s != null && (s.StartsWith("msft2009:") || s.StartsWith("msft2005:")))
            {
                Console.WriteLine($"[Esi] {s}");
            }
        }

        #endregion

        #region PidGenX调用逻辑（无修改，已修复PID=null问题）
        private static void CallPidGenX()
        {
            Console.WriteLine("==================== 开始调用PidGenX ====================");
            if (!File.Exists(configPath))
            {
                Console.WriteLine($"❌ 配置文件不存在：{configPath}");
                Console.WriteLine($"提示：请将pkconfig_winNext.xrm-ms放在程序运行目录下");
                return;
            }
            IntPtr getPidGenXAddr = GetProcAddress(_hModule, "PidGenX");
            if (getPidGenXAddr == IntPtr.Zero) return;

            _nativePidGenX = Marshal.GetDelegateForFunctionPointer<DelegatePidGenX>(getPidGenXAddr);

            IntPtr pProductID = IntPtr.Zero;
            IntPtr pDigitalProductID = IntPtr.Zero;
            IntPtr pDigitalProductID4 = IntPtr.Zero;

            try
            {
                // 1. 分配内存
                pProductID = Marshal.AllocHGlobal(100);
                pDigitalProductID = Marshal.AllocHGlobal(164);
                pDigitalProductID4 = Marshal.AllocHGlobal(1272);

                // 2. 使用安全的方式清零内存 (不要用那个 RtlZeroMemory)
                byte[] zeroBuffer = new byte[1272]; // 最大的一个
                Marshal.Copy(zeroBuffer, 0, pProductID, 100);
                Marshal.Copy(zeroBuffer, 0, pDigitalProductID, 164);
                Marshal.Copy(zeroBuffer, 0, pDigitalProductID4, 1272);

                // 3. 严格初始化结构体头部 (这是决定返回码的关键)
                // 第1个参数: ProductID 结构
                Marshal.WriteInt32(pProductID, 0, 50);

                // 第2个参数: DigitalProductID 结构
                Marshal.WriteInt32(pDigitalProductID, 0, 164);

                // 第3个参数: DigitalProductID4 结构
                // 注意：这里必须写 0x000004F8 (即1272)，且版本号要对
                Marshal.WriteInt32(pDigitalProductID4, 0, 1272);
                // 这里的 0x04 是版本号，通常在偏移 4 的位置 (Int32)
                Marshal.WriteInt32(pDigitalProductID4, 4, 4);

                // 4. 发起调用
                int retCode = _nativePidGenX(
                    TEST_PRODUCT_KEY,
                    configPath,
                    "55041",
                    IntPtr.Zero,
                    pProductID,
                    pDigitalProductID,
                    pDigitalProductID4
                );

                if (retCode == 0)
                {
                    Console.WriteLine("✅ GetPidGenX调用成功");
                    GetpDigitalProductID(pDigitalProductID);
                    GetDigitalProductId4(pDigitalProductID4);
                }
                else
                {
                    Console.WriteLine($"❌ 调用失败，返回码: {retCode} (0x{retCode:X8})");
                    // 如果 retCode 是 -2147024809，说明上面 WriteInt32 的某个 Size 还是不对
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ 异常：{ex.Message}");
            }
            finally
            {
                // 5. 释放非托管资源
                if (pProductID != IntPtr.Zero) Marshal.FreeHGlobal(pProductID);
                if (pDigitalProductID != IntPtr.Zero) Marshal.FreeHGlobal(pDigitalProductID);
                if (pDigitalProductID4 != IntPtr.Zero) Marshal.FreeHGlobal(pDigitalProductID4);
            }
        }
        #endregion

        public static void GetpDigitalProductID(IntPtr pDigitalProductID)
        {
            if (pDigitalProductID == IntPtr.Zero) return;

            // 1. 提取 Product ID (偏移 0x08, 长度 28)
            // 覆盖 "00378-60" + "425-63872-AA693"
            string fullId = ReadStringByOffset(pDigitalProductID, 0x08, 28);

            // 2. 提取 Edition ID 主体 (偏移 0x24, 长度 12)
            // 对应 "[RS1]res-v37"
            string editionBase = ReadStringByOffset(pDigitalProductID, 0x24, 12);

            // 3. 提取尾缀 (偏移 0x30, 长度 2)
            // 对应 "86"
            string suffix = ReadStringByOffset(pDigitalProductID, 0x30, 2);

            // 输出结果
            Console.WriteLine($"Full ID: {fullId}");
            Console.WriteLine($"Edition: {editionBase}{suffix}");
        }

        /// <summary>
        /// 从内存偏移处读取指定长度并清洗非打印字符
        /// </summary>
        private static string ReadStringByOffset(IntPtr basePtr, int offset, int length)
        {
            byte[] buffer = new byte[length];
            // 从基址 + 偏移量 处拷贝内存
            Marshal.Copy(IntPtr.Add(basePtr, offset), buffer, 0, length);

            // 清洗数据：只保留可见 ASCII 字符 (32-126)，跳过 0x00 等控制符
            StringBuilder sb = new StringBuilder();
            foreach (byte b in buffer)
            {
                if (b >= 32 && b <= 126)
                {
                    sb.Append((char)b);
                }
            }
            return sb.ToString();
        }

        public static void GetDigitalProductId4(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero) return;

            // 1. 提取 ANSI 字段 (使用之前的 CleanAscii 逻辑)
            string pid = ReadAnsi(ptr, 0x08, 24 * 4);
            string internalVer = ReadAnsi(ptr, 0x84, 19 * 4);

            // 2. 提取 Unicode 字段 (使用 Marshal 直接读取宽字符)
            // Edition Name (0x118)
            string editionDisplayName = Marshal.PtrToStringUni(IntPtr.Add(ptr, 0x118));

            // Volume Channel (0x3F8) -> 提取 "Volume:MAK"
            string volumeChannel = Marshal.PtrToStringUni(IntPtr.Add(ptr, 0x3F8));

            // Volume Type (0x478) -> 提取 "Volume"
            string volumeType = Marshal.PtrToStringUni(IntPtr.Add(ptr, 0x478));

            // 输出提取结果
            Console.WriteLine($"PID: {pid}");
            Console.WriteLine($"Internal Version: {internalVer}");
            Console.WriteLine($"Edition: {editionDisplayName}");
            Console.WriteLine($"Channel: {volumeChannel}");
            Console.WriteLine($"Type: {volumeType}");
        }
        /// <summary>
        /// 精确读取 ANSI 字符串并清洗多余的空字符
        /// </summary>
        private static string ReadAnsi(IntPtr ptr, int offset, int len)
        {
            byte[] buf = new byte[len];
            Marshal.Copy(IntPtr.Add(ptr, offset), buf, 0, len);
            return Encoding.ASCII.GetString(buf).Replace("\0", "").Trim();
        }

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