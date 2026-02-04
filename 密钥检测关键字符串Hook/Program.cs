
using SppTokenGenerator;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

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
        private static string ProductKeys = "F3RT8-NTK22-D4H84-T83DJ-D9MP6";
        static void Main(string[] args)
        {

            ActConfigKeyGenerate(); //payload 算法还有问题 
            //==========================================================
            
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

            //获取安装ID
            IntPtr procAddress1 = GetProcAddress(hModule, "GetPKeyData");
            DelegateGetPKeyData delegateForFunctionPointer1 = Marshal.GetDelegateForFunctionPointer<DelegateGetPKeyData>(procAddress1);
            string IID; string Description, channel, subType; StringBuilder PID = null;
            int num1 = delegateForFunctionPointer1(ProductKeys, pkeyconfigxml, null, null, IntPtr.Zero, IntPtr.Zero, out IID, out Description, out channel, out subType, PID);
            Console.WriteLine(IID);


            IntPtr procAddress = GetProcAddress(hModule, "PidGenX");
            fnPidGenX delegateForFunctionPointer = Marshal.GetDelegateForFunctionPointer<fnPidGenX>(procAddress);

            //四处HookAPI

            //如果要hook该函数  
            Int32 a = hModule.ToInt32();
            IntPtr b = new IntPtr(hModule.ToInt32() + 50073);
            Console.WriteLine("dll基址：0x" + hModule.ToString("X8"));
            Console.WriteLine("研究hook函数地址1：0x" + IntPtr.Add(hModule, 0xA9CB).ToString("X8"));
            Console.WriteLine("研究hook函数地址2：0x" + IntPtr.Add(hModule, 0xB0EC).ToString("X8"));//0xB0EC
            Console.WriteLine("按任意健开始hook，hook函数地址：0x" + b.ToString("X8"));
            Console.ReadLine();
            IntPtr HookPtr = FastCall.WrapStdCallInFastCall(Marshal.GetFunctionPointerForDelegate(new GetPID2Delegate(MyGetPID2)));
            HookAPI HookFunc = new HookAPI(new IntPtr(hModule.ToInt32() + 50073), HookPtr);
            HookAPI.Install();

            //另外一种hook 写法 HookAPI与Hook类
            //Hook hook = new Hook(new IntPtr(hModule.ToInt32() + 50073), HookPtr);
            //Hook.Install();

            //ProductKeyUtilities.dll偏移地址55041 和 50252 都是； pidgenx.dll的偏移x86的偏移是5088E， x64的是1E938
            int num = delegateForFunctionPointer(ProductKeys, pkeyconfigxml, "55041", (IntPtr)0, intPtr, intPtr2, intPtr3);
            Console.WriteLine(num.ToString());
            HookAPI.Unistall();

            //HookAPI.Unistall();

            Console.ReadLine();
        }
        private static int MyGetPID2(IntPtr intptr_1, IntPtr intptr_2, int int_0, int int_1, int int_2, IntPtr intptr_3)
        {
            //两处HookAPI
            // Hook.Unistall();
            HookAPI.Unistall();

            int num = 0;
            checked
            {
                if (hModule_base != IntPtr.Zero)
                {
                    WrapperGetPID2Delegate wrapperGetPID2Delegate = FastCall.StdcallToFastcall<WrapperGetPID2Delegate>(FastCall.InvokePtr);
                    num = wrapperGetPID2Delegate(new IntPtr(hModule_base.ToInt32() + 50073), intptr_1, intptr_2, int_0, int_1, int_2, intptr_3);
                    Console.WriteLine("num:" + num);
                    if (num == 0)
                    {
                        //Marshal.PtrToStringUni(intptr_3);
                        object obj2 = Marshal.PtrToStructure(intptr_1, typeof(FileTime));
                        FileTime fileTime = (obj2 != null) ? ((FileTime)obj2) : default(FileTime);
                        Console.WriteLine(fileTime.ActConfigKey);
                    }
                }

                HookAPI.Install();
                // Hook.Install();
                return num;
            }

        }
        static void ActConfigKeyGenerate()
        {
            try
            {
                // 解决控制台中文乱码
                Console.OutputEncoding = Encoding.UTF8;
                Console.InputEncoding = Encoding.UTF8;

                // 加载pkeyconfig.xml（确保文件在程序运行目录）
                string pkeyPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "pkconfig_winNext.xrm-ms");
                if (!File.Exists(pkeyPath))
                {
                    Console.WriteLine($"❌ 致命错误：未找到pkeyconfig.xml，请将文件放在程序运行目录！");
                    return;
                }

                // 初始化PKeyConfig配置
                Console.WriteLine("🔍 加载并初始化PKeyConfig...");
                WindowsActivationEngine.Initialize(File.ReadAllText(pkeyPath, Encoding.UTF8));
                Console.WriteLine("✅ PKeyConfig初始化成功");

                // 测试密钥（标准29位，带4个分隔符，可替换为自己的密钥）
                string testKey = ProductKeys;
                Console.WriteLine($"\n⚙️  解析目标密钥：{testKey}");

                // 生成激活Token（含详细信息）
                var (edition, actConfigId, token) = WindowsActivationEngine.AutoGenerateTokenWithDetails(testKey);

                // 输出生成结果
                Console.WriteLine("\n=============================================");
                Console.WriteLine($"🎯 匹配EditionId：{edition}");
                Console.WriteLine($"🆔 匹配ActConfigId：{actConfigId}");
                Console.WriteLine($"🔑 生成msft2009 Token：\n{token}");
                Console.WriteLine("=============================================\n");

                // 验证是否与目标Token完全匹配
                string targetToken = "msft2009:4de7cb65-cdf1-4de9-8ae8-e3cce27b9f2c&bFnJEXYG8EMpD35+/A==";
                if (token == targetToken)
                    Console.WriteLine("✅ 终极成功！生成的Token与Hook目标100%完全一致！");
                else
                {
                    Console.WriteLine("⚠️  Token生成成功，若未匹配目标，请检查：");
                    Console.WriteLine("   1. pkeyconfig.xml是否为对应系统版本的原生文件；");
                    Console.WriteLine("   2. 测试密钥是否为对应Edition的有效密钥；");
                    Console.WriteLine($"🔍 目标Hook Token：{targetToken}");
                }
            }
            catch (Exception ex)
            {
                // 异常详细信息输出，便于调试
                Console.WriteLine($"\n❌ 执行失败：{ex.Message}");
                if (ex.InnerException != null)
                    Console.WriteLine($"🔍 内部错误：{ex.InnerException.Message}");
                Console.WriteLine($"📜 错误堆栈：{ex.StackTrace}");
            }
            finally
            {
                Console.WriteLine("\n按任意键退出...");
                Console.ReadKey();
            }
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