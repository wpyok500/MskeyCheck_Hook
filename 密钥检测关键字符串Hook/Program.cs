using Microsoft.SqlServer.Server;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace 密钥检测关键字符串Hook
{
    class Program
    {
        /// <summary>
        /// 核心委托：匹配Sub551FA9CB的参数，显式StdCall，由汇编跳板转__fastcall  //偏移0xA9CB ，基址0x55150000
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        public delegate int Sub551FA9CBDelegate(
            IntPtr a1,        // ECX → &v28（原生__fastcall，由汇编跳板传入）
            string a2,        // EDX → 格式化字符串（原生__fastcall，由汇编跳板传入）
            IntPtr args       // 栈传 → va_list（可变参，直接透传）
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]  //偏移0xA9CB
        private delegate int WrapperSub551FA9CBDelegate(IntPtr functionPtr, IntPtr a1, string a2, IntPtr args);

        //执行原生函数的委托：匹配Sub551FA9CB的参数，显式FastCall
        [UnmanagedFunctionPointer(CallingConvention.FastCall, CharSet = CharSet.Unicode)]
        private delegate int NativeSub551FA9CB(IntPtr a1,string format,IntPtr args);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        public delegate int Sub7BBCC0ECDelegate(
            IntPtr a1,        // ECX：对象指针
            int a2,           // EDX
            int a3,           // stack
            IntPtr buffer     // stack：wchar_t*
        );
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int WrapperSub7BBCC0ECDelegate(IntPtr functionPtr, IntPtr a1, int a2, int a3, IntPtr buffer);

        [DllImport("kernel32.dll")]
        internal static extern bool RtlZeroMemory(IntPtr destination, int length);

        // Token: 0x06000094 RID: 148
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool SetDllDirectory(string lpPathName);

        // Token: 0x06000095 RID: 149
        [DllImport("kernel32", SetLastError = true)]
        internal static extern IntPtr LoadLibrary(string lpFileName);

        // Token: 0x06000096 RID: 150
        [DllImport("Kernel32.dll")]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        // Token: 0x06000097 RID: 151
        [DllImport("kernel32.dll")]
        internal static extern bool FreeLibrary(IntPtr hModule);
        static string string_0 = Environment.CurrentDirectory + "\\";
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int fnPidGenX(string ProuctKey, string PkeyPath, string MPCID, IntPtr UnknownUsage, IntPtr PID2, IntPtr PID3, IntPtr PID4);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int DelegateGetPKeyData(string ProductKey, string PkeyConfigPath, string MPCID, string pwszPKeyAlgorithm, IntPtr OemId, IntPtr OtherId, out string IID, out string Description, out string channel, out string subType, StringBuilder PID);

        private static IntPtr hModule_base = IntPtr.Zero;
        private static Int32 hookFOffset = 0xC0EC;   

        static void Main(string[] args)
        {

            string ProductKeys = "VK7JG-NPHTM-C97JM-9MPGT-3V66T";
            string pkeyconfigxml = System.Environment.CurrentDirectory + "\\pkconfig_winNext.xrm-ms";
            IntPtr intPtr = Marshal.AllocHGlobal(100);
            RtlZeroMemory(intPtr, 50);
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
            Console.WriteLine("模块基址：0x" + hModule.ToString("X8"));
            Console.WriteLine("研究hook函数地址1：0x" + IntPtr.Add(hModule, 0xA9CB).ToString("X8"));
            Console.WriteLine("研究hook函数地址2：0x" + IntPtr.Add(hModule, 0xC0EC).ToString("X8"));//0xC0EC

            Int32 a = hModule.ToInt32();
            Int32 b = hModule.ToInt32() + hookFOffset;
            Console.WriteLine("hook函数偏移基址：0x" + new IntPtr(hModule_base.ToInt32() + hookFOffset).ToString("X8"));
            Console.WriteLine("按任意健开始hook");
            Console.ReadLine();

            ////如果要hook该函数  
            //IntPtr HookPtr = FastCall.WrapStdCallInFastCall(Marshal.GetFunctionPointerForDelegate(new Sub7BBCC0ECDelegate(MyGetPID2)));
            //HookAPI HookFunc = new HookAPI(new IntPtr(hModule_base.ToInt32() + hookFOffset), HookPtr);
            //HookAPI.Install();

            //另外一种hook 写法 HookAPI与Hook类
            //Hook hook = new Hook(new IntPtr(hModule.ToInt32() + 50073), HookPtr);
            //Hook.Install();

            //获取安装ID
            IntPtr procAddress1 = GetProcAddress(hModule, "GetPKeyData");
            DelegateGetPKeyData delegateForFunctionPointer1 = Marshal.GetDelegateForFunctionPointer<DelegateGetPKeyData>(procAddress1);
            string IID; string Description, channel, subType; StringBuilder PID = null;
            int num1 = delegateForFunctionPointer1(ProductKeys, pkeyconfigxml, null, null, IntPtr.Zero, IntPtr.Zero, out IID, out Description, out channel, out subType, PID);
            Console.WriteLine(IID);


            //HookAPI.Unistall();

            // 释放非托管内存
            Marshal.FreeHGlobal(intPtr);
            Marshal.FreeHGlobal(intPtr2);
            Marshal.FreeHGlobal(intPtr3);
            // 释放非托管模块
            if (hModule != IntPtr.Zero) FreeLibrary(hModule);
            hModule_base = IntPtr.Zero;

            Console.ReadLine();
        }

        private static int _getPid2CallDepth = 0;

        private static int MyGetPID2(IntPtr a1, int a2, int a3, IntPtr buffer)
        {
            int depth = ++_getPid2CallDepth;
            bool isTopCall = (depth == 1);

            if (isTopCall)
                HookAPI.Unistall();   // ✅ 只在最外层卸载

            int num;
            try
            {
                WrapperSub7BBCC0ECDelegate wrapper =
                    FastCall.StdcallToFastcall<WrapperSub7BBCC0ECDelegate>(FastCall.InvokePtr);

                num = wrapper(hModule_base + hookFOffset, a1, a2, a3, buffer);

                Console.WriteLine($"[sub_7BBCC0EC] depth={depth}, num=0x{num:X8}");

                // ✅ 第二层（真正写数据的那次）
                if (depth == 2 && a1 != IntPtr.Zero)
                {
                    IntPtr textPtr = Marshal.ReadIntPtr(a1, 0x14);
                    string text = Marshal.PtrToStringUni(textPtr);
                    Console.WriteLine($"🔥 SECOND CALL TEXT = \"{text}\"");
                }
            }
            finally
            {
                if (isTopCall)
                    HookAPI.Install();  // ✅ 只在最外层恢复

                _getPid2CallDepth--;
            }

            return num;
        }

    }
}