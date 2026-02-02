using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class FastCall
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint size, uint allocationType, uint protect);

    public static IntPtr InvokePtr { get; private set; }
    public static List<IntPtr> FastCallWrappers = new List<IntPtr>();

    private static byte[] InvokeCode = { 0x5A, 0x36, 0x87, 0x54, 0x24, 0x08, 0x58, 0x59, 0xFF, 0xE0 };
    private static byte[] WrapperCode = { 0x58, 0x52, 0x51, 0x50, 0x68, 0x00, 0x00, 0x00, 0x00, 0xC3 };

    static FastCall()
    {
        InvokePtr = VirtualAlloc(IntPtr.Zero, (uint)InvokeCode.Length, 0x1000, 0x40);
        Marshal.Copy(InvokeCode, 0, InvokePtr, InvokeCode.Length);
    }

    public static IntPtr WrapStdCallInFastCall(IntPtr stdCallPtr)
    {
        IntPtr result = VirtualAlloc(IntPtr.Zero, (uint)WrapperCode.Length, 0x1000, 0x40);
        Marshal.Copy(WrapperCode, 0, result, WrapperCode.Length);
        Marshal.WriteIntPtr(result, 5, stdCallPtr);
        return result;
    }

    public static T StdcallToFastcall<T>(IntPtr functionPtr)
    {
        List<byte> wrapper = new List<byte> { 0x58, 0x59, 0x5A, 0x50, 0x68 };
        wrapper.AddRange(BitConverter.GetBytes(functionPtr.ToInt32()));
        wrapper.Add(0xC3);

        IntPtr wrapperPtr = Marshal.AllocHGlobal(wrapper.Count);
        Marshal.Copy(wrapper.ToArray(), 0, wrapperPtr, wrapper.Count);
        FastCallWrappers.Add(wrapperPtr);
        return (T)(object)Marshal.GetDelegateForFunctionPointer(functionPtr, typeof(T));
    }
}