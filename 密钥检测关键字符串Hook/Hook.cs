﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace 密钥检测关键字符串Hook
{
    public unsafe class Hook
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

        public Hook(IntPtr target, IntPtr hook)
        {
            if (Environment.Is64BitProcess)
                throw new NotSupportedException("X64 not supported, TODO");

            TargetAddress = target;
            HookAddress = hook;

            m_OriginalBytes = new byte[5];

            //.NET写法
            IntPtr intPtr = Marshal.UnsafeAddrOfPinnedArrayElement(m_OriginalBytes, 0);
            ProtectionSafeMemoryCopy(intPtr, target, m_OriginalBytes.Length);

            //C++写法
            //fixed (byte* p = m_OriginalBytes)
            //{
            //    ProtectionSafeMemoryCopy(new IntPtr(p), target, m_OriginalBytes.Length);
            //}
        }

        public static void Install()
        {
            var jmp = CreateJMP(TargetAddress, HookAddress);
            fixed (byte* p = jmp)
            {
                ProtectionSafeMemoryCopy(TargetAddress, new IntPtr(p), jmp.Length);
            }
        }

        public static void Unistall()
        {
            fixed (byte* p = m_OriginalBytes)
            {
                ProtectionSafeMemoryCopy(TargetAddress, new IntPtr(p), m_OriginalBytes.Length);
            }
        }

        static void ProtectionSafeMemoryCopy(IntPtr dest, IntPtr source, int count)
        {
            // UIntPtr = size_t
            var bufferSize = new UIntPtr((uint)count);
            VirtualProtectionType oldProtection, temp;

            // unprotect memory to copy buffer
            if (!VirtualProtect(dest, bufferSize, VirtualProtectionType.ExecuteReadWrite, out oldProtection))
                throw new Exception("Failed to unprotect memory.");

            byte* pDest = (byte*)dest;
            byte* pSrc = (byte*)source;

            // copy buffer to address
            for (int i = 0; i < count; i++)
            {
                *(pDest + i) = *(pSrc + i);
            }

            // protect back
            if (!VirtualProtect(dest, bufferSize, oldProtection, out temp))
                throw new Exception("Failed to protect memory.");
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
