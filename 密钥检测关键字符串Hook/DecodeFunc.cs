using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

public class DecodeFunc
{
    // Token: 0x06000056 RID: 86 RVA: 0x000589E8 File Offset: 0x00056BE8
    public static void init()
    {
        DecodeFunc.dll = new DLLFromMemory(PeArray.rawData86);
        IntPtr intPtr = DecodeFunc.VirtualAlloc(IntPtr.Zero, (uint)DecodeFunc.InvokeCode.Length, DecodeFunc.AllocationType.Commit, DecodeFunc.MemoryProtection.ExecuteReadWrite);
        Marshal.Copy(DecodeFunc.InvokeCode, 0, intPtr, DecodeFunc.InvokeCode.Length);
        DecodeFunc.fPublicKeyValue = DecodeFunc.StdcallToFastcall<DecodeFunc.PublicKeyValueDelegate>(intPtr);
        IntPtr intPtr2 = DecodeFunc.VirtualAlloc(IntPtr.Zero, (uint)DecodeFunc.InvokeCode.Length, DecodeFunc.AllocationType.Commit, DecodeFunc.MemoryProtection.ExecuteReadWrite);
        Marshal.Copy(DecodeFunc.InvokeCode, 0, intPtr2, DecodeFunc.InvokeCode.Length);
        DecodeFunc.pVertifyKeysBytes = DecodeFunc.StdcallToFastcall<DecodeFunc.vertifyKeysBytesDelegate>(intPtr2);
        IntPtr intPtr3 = DecodeFunc.VirtualAlloc(IntPtr.Zero, (uint)DecodeFunc.InvokeCode.Length, DecodeFunc.AllocationType.Commit, DecodeFunc.MemoryProtection.ExecuteReadWrite);
        Marshal.Copy(DecodeFunc.InvokeCode, 0, intPtr3, DecodeFunc.InvokeCode.Length);
        DecodeFunc.pCaclByte = DecodeFunc.StdcallToFastcall<DecodeFunc.CaclByteDelegate>(intPtr3);
        DecodeFunc.pGetOtherIdStr = (DecodeFunc.GetOtherIdStrDelegate)Marshal.GetDelegateForFunctionPointer(new IntPtr(DecodeFunc.dll.pCode.ToInt32() + 4381), typeof(DecodeFunc.GetOtherIdStrDelegate));
        Task.Run(delegate
        {
            DecodeFunc.LoadPublicKeyData();
        });
    }

    // Token: 0x06000057 RID: 87 RVA: 0x00058B08 File Offset: 0x00056D08
    private static void LoadPublicKeyData()
    {
        foreach (KeyValuePair<int, byte[]> keyValuePair in ConfigData2005.PublicKeyPart2)
        {
            try
            {
                int[] array = new int[7];
                int[] array2 = new int[5];
                byte[] array3 = ConfigData2005.PublicKeyPart1.Concat(keyValuePair.Value).ToArray<byte>();
                int num = DecodeFunc.PublicKeyValue(array, array3, 1579U, array2);
                bool flag = num == 1;
                if (flag)
                {
                    byte[] array4 = new byte[200];
                    Marshal.Copy(new IntPtr(array[6]), array4, 0, array4.Length);
                    byte[] array5 = array4.Skip(44).Take(44).ToArray<byte>();
                    byte[] array6 = array4.Skip(88).Take(44).ToArray<byte>();
                    DecodeFunc.PublicDict[keyValuePair.Key] = Tuple.Create<byte[], byte[]>(array5, array6);
                }
            }
            catch
            {
            }
        }
    }

    // Token: 0x06000058 RID: 88 RVA: 0x00058C20 File Offset: 0x00056E20
    public static int PublicKeyValue(int[] pMem, byte[] bPublicKey, uint dwSize, int[] retValue)
    {
        IntPtr intPtr = Marshal.AllocHGlobal(bPublicKey.Length);
        Marshal.Copy(bPublicKey, 0, intPtr, bPublicKey.Length);
        return DecodeFunc.fPublicKeyValue(new IntPtr(DecodeFunc.dll.pCode.ToInt32() + 4281), pMem, bPublicKey, 1579U, retValue);
    }

    // Token: 0x06000059 RID: 89 RVA: 0x00058C74 File Offset: 0x00056E74
    public static int VertifyKeysBytes(byte[] pMem1, byte[] pMem2, byte[] pMem3, byte[] ifTrue, byte[] Dst, int[] retValue)
    {
        IntPtr intPtr = DecodeFunc.VirtualAlloc(IntPtr.Zero, (uint)DecodeFunc.InvokeCode.Length, DecodeFunc.AllocationType.Commit, DecodeFunc.MemoryProtection.ExecuteReadWrite);
        Marshal.Copy(DecodeFunc.InvokeCode, 0, intPtr, DecodeFunc.InvokeCode.Length);
        DecodeFunc.vertifyKeysBytesDelegate vertifyKeysBytesDelegate = DecodeFunc.StdcallToFastcall<DecodeFunc.vertifyKeysBytesDelegate>(intPtr);
        return vertifyKeysBytesDelegate(new IntPtr(DecodeFunc.dll.pCode.ToInt32() + 4316), pMem1, pMem2, pMem3, ifTrue, Dst, retValue);
    }

    // Token: 0x0600005A RID: 90 RVA: 0x00058CE4 File Offset: 0x00056EE4
    public static int CaclByte(byte[] pMem1, byte[] pMem2, byte[] Dst, int[] retValue)
    {
        return DecodeFunc.pCaclByte(new IntPtr(DecodeFunc.dll.pCode.ToInt32() + 4366), pMem1, pMem2, Dst, retValue);
    }


    // Token: 0x0600005C RID: 92
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr hProcess, uint size, DecodeFunc.AllocationType flAllocationType, DecodeFunc.MemoryProtection flProtect);

    // Token: 0x0600005D RID: 93 RVA: 0x00058D44 File Offset: 0x00056F44
    private static T StdcallToFastcall<T>(IntPtr functionPtr)
    {
        List<byte> list = new List<byte>();
        list.Add(88);
        list.Add(89);
        list.Add(90);
        list.Add(80);
        list.Add(104);
        list.AddRange(BitConverter.GetBytes(functionPtr.ToInt32()));
        list.Add(195);
        IntPtr intPtr = Marshal.AllocHGlobal(list.Count);
        Marshal.Copy(list.ToArray(), 0, intPtr, list.Count);
        bool flag = DecodeFunc.FastCallWrappers == null;
        if (flag)
        {
            DecodeFunc.FastCallWrappers = new List<IntPtr>();
        }
        DecodeFunc.FastCallWrappers.Add(intPtr);
        return (T)((object)Marshal.GetDelegateForFunctionPointer(functionPtr, typeof(T)));
    }


    public static DLLFromMemory dll;
    // Token: 0x0400006E RID: 110
    public static Dictionary<int, Tuple<byte[], byte[]>> PublicDict = new Dictionary<int, Tuple<byte[], byte[]>>();

    // Token: 0x0400006F RID: 111
    private static DecodeFunc.PublicKeyValueDelegate fPublicKeyValue;

    // Token: 0x04000070 RID: 112
    private static DecodeFunc.vertifyKeysBytesDelegate pVertifyKeysBytes;

    // Token: 0x04000071 RID: 113
    private static DecodeFunc.CaclByteDelegate pCaclByte;

    // Token: 0x04000072 RID: 114
    private static DecodeFunc.GetOtherIdStrDelegate pGetOtherIdStr;

    // Token: 0x04000073 RID: 115
    private static List<IntPtr> FastCallWrappers;

    // Token: 0x04000074 RID: 116
    private static byte[] InvokeCode = new byte[] { 90, 54, 135, 84, 36, 8, 88, 89, byte.MaxValue, 224 };

    // Token: 0x04000075 RID: 117
    private static byte[] WrapperCode = new byte[] { 88, 82, 81, 80, 104, 0, 0, 0, 0, 195 };

    // Token: 0x02000015 RID: 21
    // (Invoke) Token: 0x06000062 RID: 98
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int PublicKeyValueDelegate(IntPtr functionPtr, int[] pMem, byte[] PublicKeyBytes, uint dwSize, int[] retValue);

    // Token: 0x02000016 RID: 22
    // (Invoke) Token: 0x06000066 RID: 102
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int vertifyKeysBytesDelegate(IntPtr functionPtr, byte[] pMem1, byte[] pMem2, byte[] pMem3, byte[] ifTrue, byte[] value, int[] retValue);

    // Token: 0x02000017 RID: 23
    // (Invoke) Token: 0x0600006A RID: 106
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int CaclByteDelegate(IntPtr functionPtr, byte[] pMem1, byte[] pMem2, byte[] Dst, int[] retValue);

    // Token: 0x02000018 RID: 24
    // (Invoke) Token: 0x0600006E RID: 110
    [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
    private delegate int GetOtherIdStrDelegate(byte[] src, int oemId, int otherId, int zero, ref IntPtr IID);

    // Token: 0x02000019 RID: 25
    public enum AllocationType
    {
        // Token: 0x04000077 RID: 119
        Commit = 4096,
        // Token: 0x04000078 RID: 120
        Reserve = 8192,
        // Token: 0x04000079 RID: 121
        Decommit = 16384,
        // Token: 0x0400007A RID: 122
        Release = 32768,
        // Token: 0x0400007B RID: 123
        Reset = 524288,
        // Token: 0x0400007C RID: 124
        Physical = 4194304,
        // Token: 0x0400007D RID: 125
        TopDown = 1048576,
        // Token: 0x0400007E RID: 126
        WriteWatch = 2097152,
        // Token: 0x0400007F RID: 127
        LargePages = 536870912
    }

    // Token: 0x0200001A RID: 26
    public enum MemoryProtection
    {
        // Token: 0x04000081 RID: 129
        Execute = 16,
        // Token: 0x04000082 RID: 130
        ExecuteRead = 32,
        // Token: 0x04000083 RID: 131
        ExecuteReadWrite = 64,
        // Token: 0x04000084 RID: 132
        ExecuteWriteCopy = 128,
        // Token: 0x04000085 RID: 133
        NoAccess = 1,
        // Token: 0x04000086 RID: 134
        ReadOnly,
        // Token: 0x04000087 RID: 135
        ReadWrite = 4,
        // Token: 0x04000088 RID: 136
        WriteCopy = 8,
        // Token: 0x04000089 RID: 137
        GuardModifierflag = 256,
        // Token: 0x0400008A RID: 138
        NoCacheModifierflag = 512,
        // Token: 0x0400008B RID: 139
        WriteCombineModifierflag = 1024
    }
}
