using Reloaded.Hooks;
using Reloaded.Hooks.Definitions;
using System;
using System.Runtime.InteropServices;
using Reloaded.Memory.Utilities;
using System.Text;

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

    // 关键：委托恢复原始签名，移除所有FunctionContext相关参数（4.3 无需）
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
    private const int HOOK_OFFSET = 0x2F60C; // 你的固定偏移量
    private static IHook<Sub_7FFBB9DBF60CDelegate> _targetHook; // 4.3 原生IHook，无需额外定义
    #endregion

    static void Main()
    {
        string productKey = "VD6RP-R2NK7-HBG8F-3DJ8T-KTPKM";
        string pkeyConfigXml = AppDomain.CurrentDomain.BaseDirectory + "pkconfig_winNext.xrm-ms";
        IntPtr hMod = IntPtr.Zero;
        IntPtr pkeyConfigPtr = IntPtr.Zero;

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
            Console.WriteLine($"✅ 动态计算Hook地址：0x{hookAddress.ToString("X16")}（基址+0x{HOOK_OFFSET:X}）");

            // 初始化并激活Reloaded.Hooks 4.3（核心适配，无任何未定义类型）
            InitReloadedHook43(hookAddress);

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
                1,
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
                Console.WriteLine($"outStr1: {Marshal.PtrToStringUni(outStr1) ?? "空"}");
                Console.WriteLine($"outStr2: {Marshal.PtrToStringUni(outStr2) ?? "空"}");
                Console.WriteLine($"outStr3: {Marshal.PtrToStringUni(outStr3) ?? "空"}");
                Console.WriteLine($"outBlob: {Marshal.PtrToStringUni(outBlob) ?? "空"}");
            }
            else
            {
                Console.WriteLine($"\n❌ GetPKeyData执行失败，错误码：0x{hr:X8}");
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
            if (_targetHook != null)
            {
                _targetHook.Disable(); // 禁用Hook
                Console.WriteLine("\n✅ Reloaded.Hooks 4.3 已安全释放");
            }
            if (pkeyConfigPtr != IntPtr.Zero) Marshal.FreeHGlobal(pkeyConfigPtr);
            if (hMod != IntPtr.Zero) FreeLibrary(hMod); // 释放DLL句柄
            Console.WriteLine("✅ 所有资源已释放完毕，按任意键退出...");
            Console.ReadKey();
        }
    }

    #region 3. Reloaded.Hooks 4.3 核心初始化（无任何未定义类型，适配标准API）
    /// <summary>
    /// 初始化Reloaded.Hooks 4.3，创建并激活Hook，无任何FunctionContext依赖
    /// </summary>
    private static void InitReloadedHook43(IntPtr hookAddress)
    {
        try
        {
            // Reloaded.Hooks 4.3 标准写法：创建Hook工厂 → 生成Hook实例 → 激活
            var hookFactory = new ReloadedHooks();
            _targetHook = hookFactory.CreateHook<Sub_7FFBB9DBF60CDelegate>(
                Hooked_Sub_7FFBB9DBF60C, // 绑定Hook处理方法
                hookAddress.ToInt64()     // 动态计算的Hook地址（64位）
            );
            //_targetHook.Enable(); // 4.3 激活Hook的标准方法（替代旧版Activate）
            _targetHook.Activate();
            if (_targetHook.IsHookActivated)
            {
                Console.WriteLine("✅ Hook激活成功！等待GetPKeyData触发...");
            }
            else
            {
                Console.WriteLine("❌ Hook激活失败！原因：1. 无管理员权限 2. 地址无效 3. DLL未加载");
                throw new Exception("Hook激活状态验证失败"); // 主动抛出异常，避免后续无意义执行
            }
            Console.WriteLine("✅ Reloaded.Hooks 4.3 Hook初始化并激活成功！");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Reloaded.Hooks 4.3 初始化失败：{ex.Message}");
            throw; // 终止程序，避免Hook失效导致逻辑异常
        }
    }

    /// <summary>
    /// Reloaded.Hooks 4.3 标准Hook处理方法（签名与委托完全一致）
    /// 核心功能：解析lpMem[0]/lpMem[1]、提取rbp-0x41/rdi、过滤msft2009:字符串
    /// </summary>
    private static long Hooked_Sub_7FFBB9DBF60C(
    IntPtr a1,
    IntPtr a2,
    IntPtr a3,
    IntPtr a4,
    IntPtr lpMem
)
    {
        if (lpMem != IntPtr.Zero)
        {
            IntPtr p1 = Marshal.ReadIntPtr(lpMem, IntPtr.Size);
            string alg = Marshal.PtrToStringUni(p1);

            if (alg != null && alg.Contains("msft2009:"))
            {
                Console.WriteLine($"🎯 捕获算法字符串: {alg}");
            }
        }

        return _targetHook.OriginalFunction(a1, a2, a3, a4, lpMem);
    }

    #endregion


}