using System;
using System.Runtime.InteropServices;

class Program
{
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
        public unsafe delegate long Sub_7FFBB9DBF60C(
        IntPtr a1,
        IntPtr a2,
        IntPtr a3,
        IntPtr a4,     // volatile int*
        IntPtr lpMem   // const wchar_t**
    );

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public unsafe delegate long Sub_7FFBB9DBF60CDelegate(
    IntPtr a1,
    IntPtr a2,
    IntPtr a3,
    IntPtr a4,     // volatile int*
    IntPtr lpMem   // const wchar_t**
    );
    [DllImport("kernel32.dll")]
    static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcessHeap();

    [DllImport("kernel32.dll")]
    static extern bool HeapFree(IntPtr hHeap, int flags, IntPtr mem);

    static void Main()
    {
        string productKey = "VD6RP-R2NK7-HBG8F-3DJ8T-KTPKM";
        string pkeyConfigXml = AppDomain.CurrentDomain.BaseDirectory + "pkconfig_winNext.xrm-ms";

        IntPtr hMod = LoadLibrary("pidgenx.dll");
        IntPtr fn = GetProcAddress(hMod, "GetPKeyData");

        var getPKeyData =
            Marshal.GetDelegateForFunctionPointer<GetPKeyDataDelegate>(fn);

        IntPtr pkeyConfigPtr = Marshal.StringToHGlobalUni(pkeyConfigXml);

        IntPtr outBlob = IntPtr.Zero;
        IntPtr outStr1 = IntPtr.Zero;
        IntPtr outStr2 = IntPtr.Zero;
        IntPtr outStr3 = IntPtr.Zero;

        //可以使用hook 工具对 关键激活参数 偏移量0x00007FFDAE29F60C−0x00007FFDAE270000=0x2F60C
        try
        {
            Console.WriteLine("dll基址：0x"+ hMod.ToString("X8"));
            Console.WriteLine("可以hook的地址：0x" + IntPtr.Add(hMod, 0x2F60C).ToString("X8"));
            Console.WriteLine("按任意健开始，执行GetPKeyData...");
            Console.ReadKey();
            int hr = getPKeyData(
                productKey,
                pkeyConfigPtr,
                null,          // ← 必须为 null
                IntPtr.Zero,
                1,
                out outBlob,
                out outStr1,
                out outStr2,
                out outStr3,
                0
            );

            if (hr >= 0)
            {
                Console.WriteLine(Marshal.PtrToStringUni(outStr1));
                Console.WriteLine(Marshal.PtrToStringUni(outStr2));
                Console.WriteLine(Marshal.PtrToStringUni(outStr3));
                Console.WriteLine(Marshal.PtrToStringUni(outBlob));
            }
            else
            {
                Console.WriteLine($"GetPKeyData failed: 0x{hr:X8}");
            }
        }
        finally
        {
            IntPtr heap = GetProcessHeap();

            if (outStr1 != IntPtr.Zero) HeapFree(heap, 0, outStr1);
            if (outStr2 != IntPtr.Zero) HeapFree(heap, 0, outStr2);
            if (outStr3 != IntPtr.Zero) HeapFree(heap, 0, outStr3);
            if (outBlob != IntPtr.Zero) HeapFree(heap, 0, outBlob);

            Marshal.FreeHGlobal(pkeyConfigPtr);
        }
        Console.ReadLine();
    }
}
