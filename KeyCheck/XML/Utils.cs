using System;
using System.Security.Cryptography;
using System.Xml.Linq;


namespace GenerateXML
{
    internal static class Utils
    {
        /// <summary>
        /// 格式化UTC时间戳
        /// </summary>
        public static string FormatTimestamp(DateTime dt)
        {
            return dt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
        }

        /// <summary>
        /// 生成Binding（.NET 4.8 兼容）
        /// </summary>
        public static string GenerateBinding()
        {
            // 16进制转字节数组
            var fixedBytes = HexStringToBytes("2A0000000100020001000100000000000000010001000100");

            // 生成18位随机字节（.NET 4.8 写法）
            var randomBytes = new byte[18];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }

            // 拼接固定字节和随机字节
            var binding = new byte[fixedBytes.Length + randomBytes.Length];
            Buffer.BlockCopy(fixedBytes, 0, binding, 0, fixedBytes.Length);
            Buffer.BlockCopy(randomBytes, 0, binding, fixedBytes.Length, randomBytes.Length);

            return Convert.ToBase64String(binding);
        }


        /// <summary>
        /// XML特殊字符转义（.NET 4.8 兼容）
        /// </summary>
        public static string XmlEscape(string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            return input
                .Replace("&", "&amp;")
                .Replace("<", "&lt;")
                .Replace(">", "&gt;");
            //.Replace("\"", "&quot;")
            //.Replace("'", "&apos;");
        }

        /// <summary>
        /// 16进制字符串转字节数组（.NET 4.8 兼容）
        /// </summary>
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
        /// 读取XML文件为XDocument
        /// </summary>
        public static XDocument ReadXmlFile(string path)
        {
            return XDocument.Load(path, LoadOptions.PreserveWhitespace);
        }

    }
}
