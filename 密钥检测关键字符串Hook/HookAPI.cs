using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace 密钥检测关键字符串Hook
{
    public unsafe class HookAPI
    {
        const string KERNEL32 = "kernel32.dll";

        [DllImport(KERNEL32)]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, VirtualProtectionType flNewProtect, out VirtualProtectionType lpflOldProtect);

        private enum VirtualProtectionType : uint
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            Readonly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        private static byte[] m_OriginalBytes;

        public static IntPtr TargetAddress { get; set; }
        public static IntPtr HookAddress { get; set; }

        public HookAPI(IntPtr target, IntPtr hook)
        {
            if (Environment.Is64BitProcess)
                throw new NotSupportedException("X64 not supported, TODO");

            TargetAddress = target;
            HookAddress = hook;

            m_OriginalBytes = new byte[5];
            ProtectionSafeMemoryCopy(m_OriginalBytes, target);
        }



        public static void Install()
        {
            byte[] jmp = CreateJMP(TargetAddress, HookAddress);
            ProtectionSafeMemoryCopy(TargetAddress, jmp);
        }

        public static void Unistall()
        {
            ProtectionSafeMemoryCopy(TargetAddress, m_OriginalBytes);
        }

        static void ProtectionSafeMemoryCopy(byte[] dest, IntPtr source)
        {
            // UIntPtr = size_t
            var bufferSize = new UIntPtr((uint)dest.Length);
            VirtualProtectionType oldProtection, temp;

            // unprotect memory to copy buffer
            if (!VirtualProtect(BytesToIntptr(dest), bufferSize, VirtualProtectionType.ExecuteReadWrite, out oldProtection))
                throw new Exception("Failed to unprotect memory.");

            // copy buffer to address
            Marshal.Copy(source, dest, 0, dest.Length);

            // protect back
            if (!VirtualProtect(BytesToIntptr(dest), bufferSize, oldProtection, out temp))
                throw new Exception("Failed to protect memory.");
        }
        static void ProtectionSafeMemoryCopy(IntPtr dest, byte[] source)
        {
            // UIntPtr = size_t
            var bufferSize = new UIntPtr((uint)source.Length);
            VirtualProtectionType oldProtection, temp;

            // unprotect memory to copy buffer
            if (!VirtualProtect(dest, bufferSize, VirtualProtectionType.ExecuteReadWrite, out oldProtection))
                throw new Exception("Failed to unprotect memory.");

            // copy buffer to address
            Marshal.Copy(source, 0, dest, source.Length);

            // protect back
            if (!VirtualProtect(dest, bufferSize, oldProtection, out temp))
                throw new Exception("Failed to protect memory.");
        }

        static IntPtr BytesToIntptr(byte[] dest)
        {
            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(dest.Length));
            Marshal.Copy(dest, 0, ptr, dest.Length);
            return ptr;
        }

        static byte[] CreateJMP(IntPtr from, IntPtr to)
        {
            return CreateJMP(new IntPtr(to.ToInt32() - from.ToInt32() - 5));
        }

        static byte[] CreateJMP(IntPtr relAddr)
        {
            var list = new List<byte>();
            // get bytes of function address
            var funcAddr32 = BitConverter.GetBytes(relAddr.ToInt32());

            // jmp [relative addr] 
            list.Add(0xE9); // jmp
            list.AddRange(funcAddr32); // func addr

            return list.ToArray();
        }
    }
}
