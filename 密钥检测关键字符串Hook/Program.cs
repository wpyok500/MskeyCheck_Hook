
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
        private static string ProductKeys = "VK7JG-NPHTM-C97JM-9MPGT-3V66T";
        static void Main(string[] args)
        {

            ActConfigKeyGenerate();
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
            // 控制台编码设置（避免中文乱码，适配所有系统）
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            try
            {
                // 步骤1：加载pkeyconfig.xml（程序同目录下）
                string pkeyConfigPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "pkconfig_winNext.xrm-ms");
                if (!File.Exists(pkeyConfigPath))
                {
                    Console.WriteLine($"❌ 错误：程序同目录下未找到pkeyconfig.xml文件");
                    Console.WriteLine($"📌 提示：请将pkeyconfig.xml放在可执行文件同一目录下");
                    return;
                }

                // 步骤2：初始化PKeyConfig配置
                Console.WriteLine("🔍 正在加载并初始化PKeyConfig配置...");
                string pkeyConfigContent = File.ReadAllText(pkeyConfigPath, Encoding.UTF8);
                WindowsActivationEngine.Initialize(pkeyConfigContent);
                Console.WriteLine("✅ PKeyConfig初始化成功！\n");

                // 步骤3：测试目标密钥VK7JG（可替换为其他密钥）
                string testProductKey = ProductKeys;
                Console.WriteLine($"⚙️  正在解析目标密钥：{testProductKey}");
                var (editionId, actConfigId, token) = WindowsActivationEngine.AutoGenerateTokenWithDetails(testProductKey);

                // 步骤4：打印结果
                Console.WriteLine("\n=============================================");
                Console.WriteLine($"🎯 匹配系统版本：{editionId}");
                Console.WriteLine($"🆔 匹配ActConfigId：{actConfigId}");
                Console.WriteLine($"🔑 生成msft2009 Token：");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(token);
                Console.ResetColor();
                Console.WriteLine("=============================================\n");

                // 步骤5：验证是否与Hook结果一致
                string targetToken = "msft2009:4de7cb65-cdf1-4de9-8ae8-e3cce27b9f2c&AAAAAHYGUKX33BIDnw==";
                if (token == targetToken)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("✅ 成功！生成的Token与SPP Hook结果完全一致！");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("⚠️  提示：Token与目标Hook结果不一致，请检查PKeyConfig或密钥");
                    Console.ResetColor();
                }
            }
            catch (Exception ex)
            {
                // 异常处理：打印详细错误信息
                Console.WriteLine($"\n❌ 执行失败：{ex.Message}");
                if (ex.InnerException != null)
                    Console.WriteLine($"🔍 内部错误：{ex.InnerException.Message}");
            }
            finally
            {
                // 等待用户退出
                Console.WriteLine("\n按任意键退出程序...");
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