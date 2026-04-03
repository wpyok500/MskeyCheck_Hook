using GenerateXML;
using Reloaded.Hooks;
using Reloaded.Hooks.Definitions;
using Reloaded.Hooks.Definitions.Enums;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public class ProductKeyHookService
{
    private const string TARGET_DLL = "ProductKeyUtilities.dll";
    private const int HOOK_OFFSET = 0x16AB0;

    private readonly string _configPath;
    private readonly string _testProductKey;
    private readonly CreateXml _createXml = new CreateXml();

    private string _capturedEsiKey = string.Empty;
    private DelegatePidGenX _nativePidGenX;
    private IAsmHook _asmHook;
    private ReloadedHooks _hooksInstance;
    private readonly OnESIDelegate _onEsi;
    private IntPtr _onEsiPtr;
    private IntPtr _hModule = IntPtr.Zero;

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    private delegate int DelegatePidGenX(
        string ProductKey, string PkeyPath, string MSPID,
        IntPtr oemId, IntPtr ProductID, IntPtr DigitalProductID, IntPtr DigitalProductID4);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void OnESIDelegate(IntPtr esi);

    public ProductKeyHookService(string configPath, string testProductKey)
    {
        _configPath = configPath;
        _testProductKey = testProductKey;
        _onEsi = OnESI;
        _onEsiPtr = Marshal.GetFunctionPointerForDelegate(_onEsi);
    }

    public KeyHookResult Run()
    {
        var res = new KeyHookResult();

        try
        {
            res.ProductKey = _testProductKey;
            _hModule = LoadLibrary(TARGET_DLL);
            if (_hModule == IntPtr.Zero)
            {
                res.Logs.Add("加载 ProductKeyUtilities.dll 失败");
                return res;
            }

            long hookAddr = _hModule.ToInt64() + HOOK_OFFSET;
            InstallAsmHook(hookAddr);
            res.Logs.Add($"Hook 已安装: 0x{hookAddr:X8}");

            CallPidGenX(res);

            res.ActConfigID = _capturedEsiKey;
            res.Success = true;
        }
        catch (Exception ex)
        {
            res.ExceptionMessage = ex.ToString();
            res.Logs.Add($"异常: {ex.Message}");
        }
        finally
        {
            Cleanup();
        }

        return res;
    }

    private void InstallAsmHook(long hookAddress)
    {
        string[] asm =
        {
                "use32",
                "pushad",
                "pushfd",
                "push esi",
                $"mov eax, {_onEsiPtr.ToInt32()}",
                "call eax",
                "add esp, 4",
                "popfd",
                "popad"
            };

        _hooksInstance = new ReloadedHooks();
        _asmHook = _hooksInstance.CreateAsmHook(asm, hookAddress, AsmHookBehaviour.ExecuteFirst).Activate();
    }

    private void OnESI(IntPtr esi)
    {
        if (esi == IntPtr.Zero || IsBadReadPtr(esi, 1)) return;
        string key = Marshal.PtrToStringUni(esi);

        if (!string.IsNullOrEmpty(key) && (key.StartsWith("msft2009:") || key.StartsWith("msft2005:")))
        {
            _capturedEsiKey = key;
        }
    }

    private void CallPidGenX(KeyHookResult res)
    {
        if (!File.Exists(_configPath))
        {
            res.Logs.Add("配置文件不存在: " + _configPath);
            return;
        }

        IntPtr pProductID = IntPtr.Zero;
        IntPtr pDigitalProductID = IntPtr.Zero;
        IntPtr pDigitalProductID4 = IntPtr.Zero;

        try
        {
            IntPtr funcAddr = GetProcAddress(_hModule, "PidGenX");
            if (funcAddr == IntPtr.Zero)
            {
                res.Logs.Add("获取 PidGenX 地址失败");
                return;
            }

            _nativePidGenX = Marshal.GetDelegateForFunctionPointer<DelegatePidGenX>(funcAddr);

            pProductID = Marshal.AllocHGlobal(100);
            pDigitalProductID = Marshal.AllocHGlobal(164);
            pDigitalProductID4 = Marshal.AllocHGlobal(1272);

            byte[] zero = new byte[1272];
            Marshal.Copy(zero, 0, pProductID, 100);
            Marshal.Copy(zero, 0, pDigitalProductID, 164);
            Marshal.Copy(zero, 0, pDigitalProductID4, 1272);

            Marshal.WriteInt32(pProductID, 0, 50);
            Marshal.WriteInt32(pDigitalProductID, 0, 164);
            Marshal.WriteInt32(pDigitalProductID4, 0, 1272);
            Marshal.WriteInt32(pDigitalProductID4, 4, 4);

            int ret = _nativePidGenX(
                _testProductKey,
                _configPath,
                "55041",
                IntPtr.Zero,
                pProductID,
                pDigitalProductID,
                pDigitalProductID4);

            res.PidGenXReturnCode = ret;

            if (ret == 0)
            {
                res.Logs.Add("PidGenX 调用成功");
                ParseDigitalProductID(pDigitalProductID, res);
                ParseDigitalProductID4(pDigitalProductID4, res);
            }
            else
            {
                res.Logs.Add($"PidGenX 失败 0x{ret:X8}");
            }
        }
        finally
        {
            if (pProductID != IntPtr.Zero) Marshal.FreeHGlobal(pProductID);
            if (pDigitalProductID != IntPtr.Zero) Marshal.FreeHGlobal(pDigitalProductID);
            if (pDigitalProductID4 != IntPtr.Zero) Marshal.FreeHGlobal(pDigitalProductID4);
        }
    }

    /// <summary>
    /// 解析 Full ID / 短版本号 (X23-57900)
    /// </summary>
    private void ParseDigitalProductID(IntPtr ptr, KeyHookResult res)
    {
        if (ptr == IntPtr.Zero) return;

        res.PID = ReadStringByOffset(ptr, 0x08, 28);
        string edBase = ReadStringByOffset(ptr, 0x24, 12);
        string edSuffix = ReadStringByOffset(ptr, 0x30, 2);
        res.EditionShort = edBase + edSuffix;
    }

    /// <summary>
    /// 解析完整 PID/渠道/MAK 类型/Description
    /// </summary>
    private void ParseDigitalProductID4(IntPtr ptr, KeyHookResult res)
    {
        if (ptr == IntPtr.Zero) return;

        res.PIDALL = ReadAnsi(ptr, 0x08, 24 * 4);
        res.InternalVersionAid = ReadAnsi(ptr, 0x84, 19 * 4);
        res.EditionName = Marshal.PtrToStringUni(IntPtr.Add(ptr, 0x118)) ?? "";
        res.Channel = Marshal.PtrToStringUni(IntPtr.Add(ptr, 0x3F8)) ?? "";
        res.KeyType = Marshal.PtrToStringUni(IntPtr.Add(ptr, 0x478)) ?? "";

        try
        {
            var cfg = PKeyConfigLoader.LoadFullConfig(_configPath);
            var desc = PKeyConfigLoader.GetProductDescription(cfg, res.InternalVersionAid, res.EditionName);
            res.ProductDescription = desc.ProductDescription;

            res.KeyCount = int.TryParse(GetCoutXML.GetCount(res.PIDALL), out int c) ? c : 0;

            if (res.KeyCount < 1)
            {
                string esi = string.IsNullOrEmpty(_capturedEsiKey)
                    ? $"msft2009:{res.PID}"
                    : _capturedEsiKey;

                res.XmlResult = _createXml.SendXML(_testProductKey, esi);
            }
        }
        catch (Exception ex)
        {
            res.ExceptionMessage = ex.Message;
        }
    }

    private string ReadStringByOffset(IntPtr basePtr, int offset, int len)
    {
        byte[] buf = new byte[len];
        Marshal.Copy(IntPtr.Add(basePtr, offset), buf, 0, len);
        StringBuilder sb = new StringBuilder();
        foreach (byte b in buf) if (b >= 32 && b <= 126) sb.Append((char)b);
        return sb.ToString();
    }

    private string ReadAnsi(IntPtr ptr, int offset, int len)
    {
        byte[] buf = new byte[len];
        Marshal.Copy(IntPtr.Add(ptr, offset), buf, 0, len);
        return Encoding.ASCII.GetString(buf).Replace("\0", "").Trim();
    }

    private void Cleanup()
    {
        _asmHook?.Disable();
        if (_hModule != IntPtr.Zero)
        {
            FreeLibrary(_hModule);
            _hModule = IntPtr.Zero;
        }
    }

    [DllImport("kernel32.dll")] private static extern bool IsBadReadPtr(IntPtr lp, uint ucb);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr LoadLibrary(string lpFileName);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)] private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32.dll")] private static extern bool FreeLibrary(IntPtr hModule);
}