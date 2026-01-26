using System;
using System.Runtime.InteropServices;
using System.Text;

namespace 密钥检测关键字符串Hook
{
    class Program
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int GetPID2Delegate(IntPtr FileTime, IntPtr MPID, int LangId, int dwBuildNumber, int unk, IntPtr DPID2);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int WrapperGetPID2Delegate(IntPtr functionPtr, IntPtr FileTime, IntPtr MPID, int LangId, int dwBuildNumber, int unk, IntPtr DPID2);

        [DllImport("kernel32.dll")]
        internal static extern bool RtlZeroMemory(IntPtr destination, int length);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll")]
        internal static extern bool FreeLibrary(IntPtr hModule);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int fnPidGenX(string ProuctKey, string PkeyPath, string MPCID, IntPtr UnknownUsage, IntPtr PID2, IntPtr PID3, IntPtr PID4);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int DelegateGetPKeyData(string ProductKey, string PkeyConfigPath, string MPCID, string pwszPKeyAlgorithm, IntPtr OemId, IntPtr OtherId, out string IID, out string Description, out string channel, out string subType, StringBuilder PID);

        private static IntPtr hModule_base = IntPtr.Zero;

        static void Main(string[] args)
        {
            // 确保以 x86 模式运行
            if (IntPtr.Size == 8) { Console.WriteLine("请在 x86 模式下运行此程序！"); return; }

            string ProductKeys = "VK7JG-NPHTM-C97JM-9MPGT-3V66T";
            string pkeyconfigxml = AppDomain.CurrentDomain.BaseDirectory + "pkconfig_winNext.xrm-ms";

            IntPtr intPtr = Marshal.AllocHGlobal(100);
            RtlZeroMemory(intPtr, 100);
            Marshal.WriteByte(intPtr, 0, 50);

            IntPtr intPtr2 = Marshal.AllocHGlobal(164);
            RtlZeroMemory(intPtr2, 164);
            Marshal.WriteByte(intPtr2, 0, 164);

            IntPtr intPtr3 = Marshal.AllocHGlobal(1272);
            RtlZeroMemory(intPtr3, 1272);
            Marshal.WriteByte(intPtr3, 0, 248);
            Marshal.WriteByte(intPtr3, 1, 4);

            IntPtr hModule = LoadLibrary("ProductKeyUtilities.dll");
            hModule_base = hModule;

            if (hModule == IntPtr.Zero) { Console.WriteLine("无法加载 DLL"); return; }

            // 获取安装ID
            IntPtr procAddress1 = GetProcAddress(hModule, "GetPKeyData");
            DelegateGetPKeyData delegateForFunctionPointer1 = Marshal.GetDelegateForFunctionPointer<DelegateGetPKeyData>(procAddress1);
            string IID, Description, channel, subType;
            delegateForFunctionPointer1(ProductKeys, pkeyconfigxml, null, null, IntPtr.Zero, IntPtr.Zero, out IID, out Description, out channel, out subType, null);
            Console.WriteLine("IID: " + IID);

            // 设置 Hook
            IntPtr hookHandler = FastCall.WrapStdCallInFastCall(Marshal.GetFunctionPointerForDelegate(new GetPID2Delegate(MyGetPID2)));

            // 注意：50073 是偏移量，必须确保对应你的 DLL 版本
            IntPtr targetAddress = new IntPtr(hModule.ToInt32() + 50073);
            HookAPI hookFunc = new HookAPI(targetAddress, hookHandler);
            HookAPI.Install();

            // 执行 PidGenX 触发 Hook
            IntPtr procAddress = GetProcAddress(hModule, "PidGenX");
            fnPidGenX delegateForFunctionPointer = Marshal.GetDelegateForFunctionPointer<fnPidGenX>(procAddress);

            int num = delegateForFunctionPointer(ProductKeys, pkeyconfigxml, "55041", IntPtr.Zero, intPtr, intPtr2, intPtr3);
            Console.WriteLine("PidGenX Result: " + num);

            HookAPI.Unistall();
            Console.ReadLine();
        }

        private static int MyGetPID2(IntPtr intptr_1, IntPtr intptr_2, int int_0, int int_1, int int_2, IntPtr intptr_3)
        {
            HookAPI.Unistall(); // 必须先卸载，否则会导致递归死循环
            int num = 0;
            try
            {
                if (hModule_base != IntPtr.Zero)
                {
                    WrapperGetPID2Delegate wrapper = FastCall.StdcallToFastcall<WrapperGetPID2Delegate>(FastCall.InvokePtr);
                    IntPtr originalFunc = new IntPtr(hModule_base.ToInt32() + 50073);
                    num = wrapper(originalFunc, intptr_1, intptr_2, int_0, int_1, int_2, intptr_3);

                    if (num == 0)
                    {
                        FileTime fileTime = (FileTime)Marshal.PtrToStructure(intptr_1, typeof(FileTime));
                        Console.WriteLine("Hooked ActConfigKey: " + fileTime.ActConfigKey);
                    }
                }
            }
            finally
            {
                HookAPI.Install();
            }
            return num;
        }
    }


    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto, Pack = 4)]
    public struct FileTime
    {
        // Token: 0x0400006D RID: 109
        public int index;

        // Token: 0x0400006E RID: 110
        [MarshalAs(UnmanagedType.LPWStr)]
        public string ActConfigKey;
    }
}