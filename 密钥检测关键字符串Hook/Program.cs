using Reloaded.Hooks;
using Reloaded.Hooks.Definitions;
using Reloaded.Hooks.Definitions.Enums;
using Reloaded.Memory.Utilities;
using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

// 移除多余的 Reloaded.Hooks.Definitions 引用（4.3 无需，避免冲突）
class Program
{
    #region 1. 原生P/Invoke委托与API定义（无修改，适配Winapi）
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
    public delegate int GetPKeyDataDelegate(
        string productKey,
        IntPtr formatArg,
        string skuOrChannel,
        IntPtr formatArg2,
        int flags,
        out IntPtr outDataBlob,
        out IntPtr outString1,
        out IntPtr outString2,
        out IntPtr outString3,
        int extraFlag
    );


    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcessHeap();

    [DllImport("kernel32.dll")]
    static extern bool HeapFree(IntPtr hHeap, int flags, IntPtr mem);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool FreeLibrary(IntPtr hModule);
    #endregion

    #region 2. Hook核心配置（基址+固定偏移量，全局Hook实例）

    private const int HOOK_OFFSET = 0x1C113; // ← 正确的 push rdi 

    //===================使用asmhook========================
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate void OnRdiDelegate(IntPtr rdi);

    private static IAsmHook _asmHook;
    private static ReloadedHooks _hooksInstance;
    private static IntPtr _callbackPtr;
    private static IntPtr hMod = IntPtr.Zero;

    static readonly OnRdiDelegate _onRdi = OnRdi;
    static IntPtr _onRdiPtr;
    //===================使用asmhook========================

    #endregion

    static void Main()
    {
        string productKey = "VD6RP-R2NK7-HBG8F-3DJ8T-KTPKM";
        string pkeyConfigXml = AppDomain.CurrentDomain.BaseDirectory + "pkconfig_winNext.xrm-ms";
        hMod = IntPtr.Zero;
        IntPtr pkeyConfigPtr = IntPtr.Zero;

        _onRdiPtr = Marshal.GetFunctionPointerForDelegate(_onRdi);

        try
        {
            // 加载pidgenx.dll并获取基址
            hMod = LoadLibrary("pidgenx.dll");
            if (hMod == IntPtr.Zero)
            {
                Console.WriteLine($"❌ 加载pidgenx.dll失败，错误码：0x{Marshal.GetLastWin32Error():X8}");
                return;
            }
            Console.WriteLine($"✅ pidgenx.dll 64位加载基址：0x{hMod.ToString("X16")}");

            // 动态计算Hook地址（核心：基址 + 固定偏移量，适配ASLR）
            IntPtr hookAddress = IntPtr.Add(hMod, HOOK_OFFSET);
            Console.WriteLine($"✅ 动态计算Hook实际地址：0x{hookAddress.ToString("X16")}（基址+0x{HOOK_OFFSET:X}）");


            // 3️⃣ 创建 AsmHook
            InstallAsmHook(hookAddress.ToInt64());

            // 初始化GetPKeyData委托，执行原始逻辑
            IntPtr fnGetPKeyData = GetProcAddress(hMod, "GetPKeyData");
            if (fnGetPKeyData == IntPtr.Zero)
            {
                Console.WriteLine($"❌ 获取GetPKeyData地址失败，错误码：0x{Marshal.GetLastWin32Error():X8}");
                return;
            }
            var getPKeyData = Marshal.GetDelegateForFunctionPointer<GetPKeyDataDelegate>(fnGetPKeyData);

            // 准备参数并执行GetPKeyData
            pkeyConfigPtr = Marshal.StringToHGlobalUni(pkeyConfigXml);
            IntPtr outBlob = IntPtr.Zero, outStr1 = IntPtr.Zero, outStr2 = IntPtr.Zero, outStr3 = IntPtr.Zero;

            Console.WriteLine("\n📌 按任意键执行GetPKeyData，Hook将自动拦截并解析数据...");
            Console.ReadKey();

            int hr = getPKeyData(
                productKey,
                pkeyConfigPtr,
                null,
                IntPtr.Zero,
                0,
                out outBlob,
                out outStr1,
                out outStr2,
                out outStr3,
                0
            );

            // 输出GetPKeyData执行结果
            if (hr >= 0)
            {
                Console.WriteLine("\n✅ GetPKeyData执行成功，原始返回结果：");
                Console.WriteLine($"outStr1密钥描述: {Marshal.PtrToStringUni(outStr1) ?? "空"}");
                Console.WriteLine($"outStr2密钥通道: {Marshal.PtrToStringUni(outStr2) ?? "空"}");
                Console.WriteLine($"outStr3密钥子类型: {Marshal.PtrToStringUni(outStr3) ?? "空"}");
                Console.WriteLine($"outBlobIID唯一标识: {Marshal.PtrToStringUni(outBlob) ?? "空"}");
            }
            else
            {
                Console.WriteLine($"\n❌ GetPKeyData执行失败，错误码：0x{hr:X8}");
            }
            //AdtConfigKeg：

            // 释放GetPKeyData返回的堆内存
            IntPtr heap = GetProcessHeap();
            if (outStr1 != IntPtr.Zero) HeapFree(heap, 0, outStr1);
            if (outStr2 != IntPtr.Zero) HeapFree(heap, 0, outStr2);
            if (outStr3 != IntPtr.Zero) HeapFree(heap, 0, outStr3);
            if (outBlob != IntPtr.Zero) HeapFree(heap, 0, outBlob);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\n❌ 程序全局异常：{ex.Message}\n{ex.StackTrace}");
        }
        finally
        {
            // 安全释放所有资源，避免泄漏
            if (_asmHook != null && _asmHook.IsEnabled)
            {
                _asmHook?.Disable();
                Console.WriteLine("\n✅ Reloaded.Hooks 4.3 已安全释放");
            }

            if (pkeyConfigPtr != IntPtr.Zero) Marshal.FreeHGlobal(pkeyConfigPtr);
            if (hMod != IntPtr.Zero) FreeLibrary(hMod); // 释放DLL句柄
            Console.WriteLine("✅ 所有资源已释放完毕，按任意键退出...");
            Console.ReadKey();
        }
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
        "use64",
        // --- 1. 保护所有易失性寄存器 ---
        "push rax",
        "push rcx",
        "push rdx",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        
        // --- 2. 深度栈对齐与环境准备 ---
        "push rbp",          // 再次备份 RBP (保持 16 字节对齐的尝试)
        "mov rbp, rsp",      // 使用 RBP 记录当前的栈顶
        "and rsp, -16",      // 强制 16 字节对齐 (非常重要！)
        "sub rsp, 20h",      // 预留 Shadow Space (32 字节)

        // --- 3. 调用托管代码 ---
        "mov rcx, rdi",      // 将原始 rdi 传给第一个参数 rcx
        $"mov rax, {_onRdiPtr.ToInt64()}",
        "call rax",

        // --- 4. 恢复环境 ---
        "mov rsp, rbp",      // 通过 RBP 直接还原对齐前的栈指针
        "pop rbp",

        // --- 5. 还原寄存器 (严格逆序) ---
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdx",
        "pop rcx",
        "pop rax"
    };



        _hooksInstance = new ReloadedHooks();

        _asmHook = _hooksInstance.CreateAsmHook(
            asm,
            hookAddress,
            AsmHookBehaviour.ExecuteFirst
        ).Activate();

        Console.WriteLine("[+] AsmHook 激活成功");
    }

    static void OnRdi(IntPtr rdi)
    {
        // 1️⃣ 永远判空
        if (rdi == IntPtr.Zero)
            return;

        // 2️⃣ 只读，不修改
        string s = Marshal.PtrToStringUni(rdi);

        // 3️⃣ 逻辑尽量轻
        if (s != null && s.StartsWith("msft2009:"))
        {
            Console.WriteLine($"[RDI] {s}");
        }
    }

}