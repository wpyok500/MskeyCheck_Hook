using System;
using System.Runtime.InteropServices;

namespace 密钥检测关键字符串Hook
{
    public class HookAPI
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private static HookAPI _instance;
        private static IntPtr _targetAddress;
        private static IntPtr _hookHandler;
        private static byte[] _originalBytes = new byte[5];
        private static byte[] _jumpBytes = new byte[5];

        public HookAPI(IntPtr targetAddress, IntPtr hookHandler)
        {
            _targetAddress = targetAddress;
            _hookHandler = hookHandler;
            _instance = this;
        }

        public static bool Install()
        {
            try
            {
                Marshal.Copy(_targetAddress, _originalBytes, 0, 5);
                int offset = _hookHandler.ToInt32() - _targetAddress.ToInt32() - 5;
                _jumpBytes[0] = 0xE9;
                Buffer.BlockCopy(BitConverter.GetBytes(offset), 0, _jumpBytes, 1, 4);

                if (!VirtualProtect(_targetAddress, 5, PAGE_EXECUTE_READWRITE, out uint oldProtect))
                    return false;

                WriteProcessMemory(GetCurrentProcess(), _targetAddress, _jumpBytes, 5, out _);
                VirtualProtect(_targetAddress, 5, oldProtect, out _);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static bool Unistall()
        {
            try
            {
                if (VirtualProtect(_targetAddress, 5, PAGE_EXECUTE_READWRITE, out uint oldProtect))
                {
                    WriteProcessMemory(GetCurrentProcess(), _targetAddress, _originalBytes, 5, out _);
                    VirtualProtect(_targetAddress, 5, oldProtect, out _);
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
    }
}