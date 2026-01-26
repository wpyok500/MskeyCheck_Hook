using System;
using System.Runtime.InteropServices;

namespace 密钥检测关键字符串Hook
{
    public unsafe class HookAPI
    {
        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        private static byte[] m_OriginalBytes = new byte[5];
        public static IntPtr TargetAddress { get; set; }
        public static IntPtr HookAddress { get; set; }

        public HookAPI(IntPtr target, IntPtr hook)
        {
            TargetAddress = target;
            HookAddress = hook;
            Marshal.Copy(target, m_OriginalBytes, 0, 5);
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

        static void ProtectionSafeMemoryCopy(IntPtr dest, byte[] source)
        {
            uint old;
            // 0x40 = PAGE_EXECUTE_READWRITE
            if (VirtualProtect(dest, (UIntPtr)source.Length, 0x40, out old))
            {
                Marshal.Copy(source, 0, dest, source.Length);
                VirtualProtect(dest, (UIntPtr)source.Length, old, out old);
            }
        }

        static byte[] CreateJMP(IntPtr from, IntPtr to)
        {
            int relAddr = to.ToInt32() - from.ToInt32() - 5;
            byte[] jmp = new byte[5];
            jmp[0] = 0xE9;
            byte[] relBytes = BitConverter.GetBytes(relAddr);
            Array.Copy(relBytes, 0, jmp, 1, 4);
            return jmp;
        }
    }
}