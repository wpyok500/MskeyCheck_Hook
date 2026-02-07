using System;
using System.Security.Cryptography;
using System.Xml.Linq;

namespace CreatXmlAct
{
    public static class Utils
    {
        /// <summary>
        /// 格式化UTC时间戳（符合原Python逻辑）
        /// </summary>
        public static string FormatTimestamp(DateTime dt)
        {
            return dt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
        }

        /// <summary>
        /// 生成Binding（原Python generate_binding逻辑）
        /// </summary>
        public static string GenerateBinding()
        {
            // .net core
            //var fixedBytes = Convert.FromHexString("2A0000000100020001000100000000000000010001000100");
            //var randomBytes = RandomNumberGenerator.GetBytes(18);
            //var binding = new byte[fixedBytes.Length + randomBytes.Length];
            //Buffer.BlockCopy(fixedBytes, 0, binding, 0, fixedBytes.Length);
            //Buffer.BlockCopy(randomBytes, 0, binding, fixedBytes.Length, randomBytes.Length);


            //.net4.8 替换原来的 Convert.FromHexString 行
            var fixedBytes = HexStringToBytes("2A0000000100020001000100000000000000010001000100");
            // 生成18位随机字节（.NET 4.8 写法）
            var randomBytes = new byte[18];
            RandomNumberGenerator.Create().GetBytes(randomBytes);

            // 拼接固定字节和随机字节
            var binding = new byte[fixedBytes.Length + randomBytes.Length];
            Buffer.BlockCopy(fixedBytes, 0, binding, 0, fixedBytes.Length);
            Buffer.BlockCopy(randomBytes, 0, binding, fixedBytes.Length, randomBytes.Length);

            return Convert.ToBase64String(binding);

            
        }

        // 新增 16进制字符串转字节数组的工具方法
        private static byte[] HexStringToBytes(string hex)
        {
            if (hex.Length % 2 != 0)
            {
                throw new ArgumentException("16进制字符串长度必须是偶数", nameof(hex));
            }

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }

        /// <summary>
        /// 编码激活数据（原Python encode_key_data逻辑）
        /// </summary>
        public static string EncodeKeyData(uint group, ulong serial, ulong security, int upgrade)
        {
            var actHash = (ulong)upgrade & 1;
            actHash |= ((ulong)serial & ((1UL << 30) - 1)) << 1;
            actHash |= ((ulong)group & ((1UL << 20) - 1)) << 31;
            actHash |= ((ulong)security & ((1UL << 53) - 1)) << 51;

            // 转13字节小端
            var actBytes = new byte[13];
            for (int i = 0; i < 13; i++)
            {
                actBytes[i] = (byte)(actHash >> (8 * i));
            }
            return Convert.ToBase64String(actBytes);
        }

        /// <summary>
        /// XML特殊字符转义（替代Python html.escape）
        /// </summary>
        public static string XmlEscape(string input)
        {
            //return XElement.Escape(input).ToString(); //.net core
            if (string.IsNullOrEmpty(input))
                return input;

            // 替换XML特殊字符（对应Python html.escape的XML转义规则）
            return input
                .Replace("&", "&amp;")
                .Replace("<", "&lt;")
                .Replace(">", "&gt;")
                .Replace("\"", "&quot;")
                .Replace("'", "&apos;");
        }

        /// <summary>
        /// 读取XML文件为XDocument
        /// </summary>
        public static XDocument ReadXmlFile(string path)
        {
            return XDocument.Load(path, LoadOptions.PreserveWhitespace);
        }
    }
}