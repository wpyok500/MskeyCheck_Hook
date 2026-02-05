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

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public unsafe delegate long Sub_7FFBB9DBF60CDelegate(
        IntPtr a1,
        IntPtr a2,
        IntPtr a3,
        IntPtr a4,     // volatile int*
        IntPtr lpMem   // const wchar_t**（核心解析目标）
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

    private const int HOOK_OFFSET = 0x2F924; // ← 正确的 mov rdi,[rbp-41] // 你的固定偏移量0x2F60C

    //===================使用asmhook========================
    private static IAsmHook _asmHook;
    private static ReloadedHooks _hooksInstance;
    private static IntPtr _callbackPtr;
    private static IntPtr hMod = IntPtr.Zero;
    //===================使用asmhook========================

    #endregion

    static void Main()
    {
        string productKey = "VD6RP-R2NK7-HBG8F-3DJ8T-KTPKM";
        string pkeyConfigXml = AppDomain.CurrentDomain.BaseDirectory + "pkconfig_winNext.xrm-ms";
        hMod = IntPtr.Zero;
        IntPtr pkeyConfigPtr = IntPtr.Zero;
        NativeState.LastMsftPtr = Marshal.AllocHGlobal(8);
        Marshal.WriteInt64(NativeState.LastMsftPtr, 0);

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

            Console.WriteLine($"[+] LastMsftPtr(native) = 0x{NativeState.LastMsftPtr.ToInt64():X16}");

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
            IntPtr msftPtr = Marshal.ReadIntPtr(NativeState.LastMsftPtr);

            if (msftPtr != IntPtr.Zero)
            {
                string s = Marshal.PtrToStringUni(msftPtr);
                Console.WriteLine($"[AdtConfigKeg：] {s}");
            }


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
            Marshal.FreeHGlobal(NativeState.LastMsftPtr);
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
        var asm = new[]
        {
            "use64",

            // rdi = msft2009 wchar_t*
            $"mov rax, {NativeState.LastMsftPtr.ToInt64()}",
            "mov [rax], rdi",
        };


        _hooksInstance = new ReloadedHooks();

        _asmHook = _hooksInstance.CreateAsmHook(
            asm,
            hookAddress,
            AsmHookBehaviour.ExecuteFirst
        ).Activate();

        Console.WriteLine("[+] AsmHook 激活成功");
    }

    static class NativeState
    {
        public static IntPtr LastMsftPtr;
    }

}