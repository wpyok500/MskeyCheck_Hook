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
		private static IntPtr hModule_base = IntPtr.Zero;
		static void Main(string[] args)
        {
			
			string ProductKeys = "VK7JG-NPHTM-C97JM-9MPGT-3V66T";
			string pkeyconfigxml = "";
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
			IntPtr procAddress = GetProcAddress(hModule, "PidGenX");
			fnPidGenX delegateForFunctionPointer = Marshal.GetDelegateForFunctionPointer<fnPidGenX>(procAddress);

			//四处HookAPI

			//如果要hook该函数  
			IntPtr HookPtr = FastCall.WrapStdCallInFastCall(Marshal.GetFunctionPointerForDelegate(new GetPID2Delegate(MyGetPID2)));
			HookAPI HookFunc = new HookAPI(new IntPtr(hModule.ToInt32() + 50073), HookPtr);
			HookAPI.Install();


			pkeyconfigxml = System.Environment.CurrentDirectory + "\\pkconfig_winNext.xrm-ms";

			//ProductKeyUtilities.dll偏移地址55041 和 50252 都是； pidgenx.dll的偏移x86的偏移是5088E， x64的是1E938
			int num = delegateForFunctionPointer(ProductKeys, pkeyconfigxml, "55041", (IntPtr)0, intPtr, intPtr2, intPtr3);
			Console.WriteLine(num.ToString());

			HookAPI.Unistall();

			Console.ReadLine();
		}
		private static int MyGetPID2(IntPtr intptr_1, IntPtr intptr_2, int int_0, int int_1, int int_2, IntPtr intptr_3)
		{
			//两处HookAPI

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
				return num;
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
