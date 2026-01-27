using System;
using System.Collections.Generic;
using System.Reflection;
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
            //string dll基址 = "0x"+hModule.ToInt32().ToString("X");
            //Console.WriteLine("hModule = 0x" + hModule.ToInt32().ToString("X"));

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
                Console.WriteLine("触发 GetPID2，开始解析 ActConfigKey");
                // 直接解析参数，不用调用原始函数
                if (intptr_1 != IntPtr.Zero)
                {
                    FileTime fileTime = Marshal.PtrToStructure<FileTime>(intptr_1);
                    Console.WriteLine("ActConfigKey: " + fileTime.ActConfigKey);

                }
                if (hModule_base != IntPtr.Zero)
                {
                    WrapperGetPID2Delegate wrapper = FastCall.StdcallToFastcall<WrapperGetPID2Delegate>(FastCall.InvokePtr);
                    IntPtr originalFunc = new IntPtr(hModule_base.ToInt32() + 50073);
                    num = wrapper(originalFunc, intptr_1, intptr_2, int_0, int_1, int_2, intptr_3);

                    if (num == 0)
                    {
                        FileTime fileTime = (FileTime)Marshal.PtrToStructure(intptr_1, typeof(FileTime));
                        Console.WriteLine("Hooked ActConfigKey: " + fileTime.ActConfigKey);

                        // 1. 智能解析intptr_3（自动识别分隔符）
                        var (fullPid, validChars) = IntPtr3Parser.ParseWithSeparator(intptr_3);

                        // 2. 输出完整解析结果
                        IntPtr3Parser.PrintFullResult(fullPid, validChars);
                    }
                }
            }
            finally
            {
                HookAPI.Install();
            }
            return num;
        }

        private static int MyGetPID2Callback(IntPtr intptr_1,IntPtr intptr_2,int int_0,int int_1,int int_2, IntPtr intptr_3)
        {
            try
            {
                var result = IntPtr3Parser.ParseWithSeparator(intptr_3);
                if (!string.IsNullOrEmpty(result.Item1))
                    IntPtr3Parser.PrintFullResult(result.Item1, result.Item2);
            }
            catch { /* Hook 场景下，绝不让异常冒泡 */ }

            IntPtr originalFunc = IntPtr.Add(hModule_base, 50073);
            var original = (GetPID2Delegate)
                Marshal.GetDelegateForFunctionPointer(originalFunc, typeof(GetPID2Delegate));

            return original(intptr_1, intptr_2, int_0, int_1, int_2, intptr_3);
        }

    }




    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct FileTime
    {
        // Token: 0x0400006D RID: 109
        public int index;

        // Token: 0x0400006E RID: 110
        [MarshalAs(UnmanagedType.LPWStr)]
        public string ActConfigKey;
    }


    public static class IntPtr3Parser
    {
        /// <summary>
        /// 智能解析 intptr_3 内存（.NET 4.8 兼容）
        /// </summary>
        public static Tuple<string, List<string>> ParseWithSeparator(
            IntPtr intptr3,
            int maxBytes = 96)
        {
            if (intptr3 == IntPtr.Zero)
                throw new ArgumentNullException("intptr3");

            byte[] buffer = new byte[maxBytes];
            Marshal.Copy(intptr3, buffer, 0, maxBytes);

            List<char> fullChars = new List<char>();
            List<string> tokens = new List<string>();

            int zeroCount = 0;

            for (int i = 0; i < buffer.Length; i++)
            {
                byte b = buffer[i];

                if (b == 0)
                {
                    zeroCount++;
                    if (zeroCount >= 2)
                        break;
                    continue;
                }

                zeroCount = 0;

                // 只允许可打印 ASCII
                if (b < 32 || b > 126)
                    continue;

                char c = (char)b;
                fullChars.Add(c);

                if (char.IsLetterOrDigit(c))
                    tokens.Add(c.ToString());
                else if (c == '-')
                    tokens.Add("-");
            }

            return Tuple.Create(new string(fullChars.ToArray()), tokens);
        }

        /// <summary>
        /// 打印 PID 的完整业务解析结果
        /// </summary>
        public static void PrintFullResult(string fullPid, List<string> tokens)
        {
            Console.WriteLine("\n===== intptr_3 解析结果 =====");
            Console.WriteLine("完整 PID：" + fullPid);
            Console.WriteLine("字符拆分：" + string.Join(" ", tokens));

            if (string.IsNullOrEmpty(fullPid))
                return;

            string[] segments = fullPid.Split(new char[] { '-' }, StringSplitOptions.RemoveEmptyEntries);

            if (segments.Length < 4)
                return;

            Console.WriteLine("\n--- PID 各段含义 ---");
            Console.WriteLine("1. 版本段：" + segments[0] + " → " + GetSegmentDesc(segments[0], 1));
            Console.WriteLine("2. 授权段：" + segments[1] + " → " + GetSegmentDesc(segments[1], 2));
            Console.WriteLine("3. 校验段：" + segments[2] + " → " + GetSegmentDesc(segments[2], 3));
            Console.WriteLine("4. 区域段：" + segments[3] + " → " + GetSegmentDesc(segments[3], 4));
        }

        /// <summary>
        /// PID 段语义解析（C# 7.3 写法）
        /// </summary>
        private static string GetSegmentDesc(string segment, int segmentType)
        {
            if (segmentType == 1)
            {
                switch (segment)
                {
                    case "00330":
                        return "Windows 10/11 专业版（零售）";
                    case "00340":
                        return "Windows 10/11 家庭版（零售）";
                    default:
                        return "未知版本类型（" + segment + ")";
                }
            }

            if (segmentType == 2)
            {
                switch (segment)
                {
                    case "80000":
                        return "零售授权（Retail）";
                    case "00000":
                        return "批量授权（VL / KMS）";
                    default:
                        return "未知授权类型（" + segment + ")";
                }
            }

            if (segmentType == 3)
            {
                if (segment == "00000")
                    return "默认校验位（未自定义）";
                return "自定义校验位（" + segment + ")";
            }

            if (segmentType == 4)
            {
                if (segment.EndsWith("766"))
                    return "全球通用区域";
                if (segment.EndsWith("866"))
                    return "中国区专属版本";
                return "区域校验码（" + segment + ")";
            }

            return "未知段";
        }
    }



}
