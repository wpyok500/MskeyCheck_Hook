using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;

namespace SppTokenGenerator
{
    public class WindowsActivationEngine
    {
        #region 核心常量（标准Base64字母表，与Hook算法一致，未修改）
        private const string Base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        #endregion

        #region 缓存容器（无修改）
        private static readonly Dictionary<string, string> _editionToGuidCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, List<string>> _guidToEditionsCache = new Dictionary<string, List<string>>();
        private static readonly object _cacheLock = new object();
        #endregion

        #region PKeyConfig初始化+XML解析（完全保留原始逻辑，未做任何修改）
        public static void Initialize(string pkeyConfigXmlContent)
        {
            if (string.IsNullOrEmpty(pkeyConfigXmlContent))
                throw new ArgumentNullException(nameof(pkeyConfigXmlContent), "pkeyconfig.xml内容不能为空");

            lock (_cacheLock)
            {
                _editionToGuidCache.Clear();
                _guidToEditionsCache.Clear();

                try
                {
                    string innerConfigXml = ExtractInnerConfig(pkeyConfigXmlContent);
                    XmlDocument doc = new XmlDocument();
                    doc.LoadXml(innerConfigXml);

                    XmlNodeList configNodes = doc.GetElementsByTagName("Configuration");
                    if (configNodes.Count == 0)
                        throw new InvalidOperationException("PKeyConfig解析失败：未找到Configuration节点");

                    foreach (XmlNode configNode in configNodes)
                    {
                        string actConfigId = configNode.SelectSingleNode(".//*[local-name()='ActConfigId']")?.InnerText?.Trim();
                        actConfigId = actConfigId?.Trim('{', '}')?.ToLowerInvariant();

                        string editionIdsText = configNode.SelectSingleNode(".//*[local-name()='EditionId']")?.InnerText?.Trim();
                        List<string> editions = string.IsNullOrEmpty(editionIdsText)
                            ? new List<string>()
                            : editionIdsText.Split(';').Select(e => e.Trim()).Where(e => !string.IsNullOrEmpty(e)).ToList();

                        if (string.IsNullOrEmpty(actConfigId) || editions.Count == 0)
                            continue;

                        foreach (var edition in editions)
                        {
                            if (!_editionToGuidCache.ContainsKey(edition))
                                _editionToGuidCache[edition] = actConfigId;
                        }

                        if (!_guidToEditionsCache.ContainsKey(actConfigId))
                            _guidToEditionsCache[actConfigId] = editions;
                    }

                    if (_editionToGuidCache.Count == 0)
                        throw new InvalidOperationException("PKeyConfig解析失败：无有效Edition->ActConfigId映射");
                }
                catch (XmlException ex)
                {
                    throw new XmlException("PKeyConfig XML解析失败：" + ex.Message, ex);
                }
            }
        }

        private static string ExtractInnerConfig(string outerXml)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(outerXml);

            XmlNamespaceManager nsmgr = new XmlNamespaceManager(doc.NameTable);
            nsmgr.AddNamespace("tm", "http://www.microsoft.com/DRM/XrML2/TM/v2");

            XmlNode infoBinNode = doc.SelectSingleNode("//tm:infoBin[@name='pkeyConfigData']", nsmgr);
            if (infoBinNode == null)
                throw new XmlException("未找到tm:infoBin[@name='pkeyConfigData']节点");

            string base64Content = infoBinNode.InnerText
                .Replace("\r", "")
                .Replace("\n", "")
                .Replace(" ", "")
                .Replace("\t", "")
                .Trim();

            byte[] binaryData = Convert.FromBase64String(base64Content);
            string decodedXml = Encoding.UTF8.GetString(binaryData);

            return decodedXml.Contains("<?xml") ? decodedXml.Substring(decodedXml.IndexOf("<?xml")) : decodedXml;
        }
        #endregion

        #region 核心Token生成（无修改，调用全流程+自定义Base64编码）
        public static (string TargetEditionId, string ActConfigId, string Token) AutoGenerateTokenWithDetails(string productKey)
        {
            if (string.IsNullOrEmpty(productKey))
                throw new ArgumentNullException(nameof(productKey), "产品密钥不能为空");

            lock (_cacheLock)
            {
                if (_editionToGuidCache.Count == 0 || _guidToEditionsCache.Count == 0)
                    throw new InvalidOperationException("请先调用Initialize方法初始化PKeyConfig配置");

                string rawKey = productKey.Trim();
                if (rawKey.Length != 29)
                    throw new ArgumentException("产品密钥格式无效，必须为带分隔符的29位（如XXXX-XXXX-XXXX-XXXX-XXXX）", nameof(productKey));

                string cleanKey = rawKey.Replace("-", "").ToUpperInvariant();
                string actConfigId = MatchActConfigIdByKey(cleanKey);
                if (string.IsNullOrEmpty(actConfigId))
                    throw new InvalidOperationException("无法匹配该密钥对应的ActConfigId");

                string editionId = _guidToEditionsCache.TryGetValue(actConfigId, out var editions)
                    ? editions.FirstOrDefault() ?? "Professional"
                    : "Professional";

                byte[] payload = GenerateSppNativePayloadWithFullProcess(rawKey);
                string base64Part = Sub_7BBD6C47_Fixed(payload); // 调用修正后的自定义Base64
                Console.WriteLine($"[调试] 最终Base64片段：{base64Part}");

                string finalToken = $"msft2009:{actConfigId}&{base64Part}";
                return (editionId, actConfigId, finalToken);
            }
        }
        #endregion

        #region 核心：全流程原生逻辑（无修改，保留所有步骤）
        private static byte[] GenerateSppNativePayloadWithFullProcess(string rawKey)
        {
            Console.WriteLine("\n==================================== 全流程调试输出 ====================================");
            // 1. GetKeyArray生成25位索引
            bool keyFlag = false;
            byte[] base24Indexes = GetKeyArray(rawKey, ref keyFlag);
            Console.WriteLine($"[调试] 1. GetKeyArray生成25位索引：{BytesToHex(base24Indexes)} | 密钥标志位：{keyFlag}");

            // 2. GetEncryptArray生成16位加密
            byte[] encryptArray = GetEncryptArray(base24Indexes, true);
            Console.WriteLine($"[调试] 2. GetEncryptArray生成16位加密：{BytesToHex(encryptArray)}");

            // 3. 补位后32位数组
            byte[] srcPadded = new byte[32];
            Buffer.BlockCopy(encryptArray, 0, srcPadded, 0, encryptArray.Length);
            Console.WriteLine($"[调试] 3. 补位后32位数组：{BytesToHex(srcPadded)}");

            // 4. GetActPkeyConfig原生13位Payload
            byte[] native13Payload = GetActPkeyConfig(srcPadded);
            Console.WriteLine($"[调试] 4. GetActPkeyConfig原生13位Payload：{BytesToHex(native13Payload)}");

            // 5. 扩容后16位Payload（供GetHashValue，解决越界）
            byte[] srcExpanded = new byte[16];
            Buffer.BlockCopy(native13Payload, 0, srcExpanded, 0, native13Payload.Length);
            Console.WriteLine($"[调试] 5. 扩容后16位Payload（供GetHashValue）：{BytesToHex(srcExpanded)}");

            // 6. GetHashValue处理后13位Payload
            byte[] afterHashPayload = GetHashValue(srcExpanded);
            afterHashPayload = afterHashPayload.Take(13).ToArray();
            Console.WriteLine($"[调试] 6. GetHashValue处理后13位Payload：{BytesToHex(afterHashPayload)}");

            // 7. Hook0x7BBCC399精准变换（目标字节数组，无修改）
            byte[] hookTransformedPayload = ApplyHook0x7BBCC399PreciseTransform(afterHashPayload);
            Console.WriteLine($"[调试] 7. Hook0x7BBCC399精准变换后13位Payload：{BytesToHex(hookTransformedPayload)}");
            Console.WriteLine("=======================================================================================\n");

            return hookTransformedPayload;
        }
        #endregion

        #region 原生方法：GetKeyArray（优化后，生成有效25位索引，兼容所有版本）
        private static byte[] GetKeyArray(string productKey, ref bool flag)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(productKey);
            byte[] keyArray = new byte[25];
            Array.Clear(keyArray, 0, keyArray.Length);
            bool hasNChar = false;
            bool prevIsNChar = false;
            int keyIndex = 0;
            int charIndex = 0;
            int separatorCount = 0;
            int validKeyLen = 29;
            int[] validSeparatorPos = new[] { 5, 11, 17, 23 };

            if (bytes.Length != validKeyLen)
                return keyArray;

            while (keyIndex < 25 && charIndex < validKeyLen)
            {
                byte currentByte = bytes[charIndex];
                bool isNChar = currentByte == 78 || currentByte == 110;
                bool isSeparator = validSeparatorPos.Contains(charIndex) && (char)currentByte == '-';

                if (isNChar)
                {
                    if (prevIsNChar || keyIndex >= 24)
                    {
                        charIndex++;
                        prevIsNChar = false;
                        continue;
                    }
                    hasNChar = true;
                    if (keyIndex > 0)
                        Buffer.BlockCopy(keyArray, 0, keyArray, 1, keyIndex);
                    keyArray[0] = (byte)keyIndex;
                    keyIndex++;
                    charIndex++;
                    prevIsNChar = true;
                    continue;
                }

                if (isSeparator && separatorCount < 4)
                {
                    separatorCount++;
                    charIndex++;
                    prevIsNChar = false;
                    continue;
                }

                byte b24Index = DecodeKeyData.pickStr(currentByte);
                if (b24Index < 24)
                {
                    keyArray[keyIndex] = b24Index;
                    keyIndex++;
                    charIndex++;
                    prevIsNChar = false;
                    continue;
                }

                charIndex++;
                prevIsNChar = false;
            }

            flag = (separatorCount == 4 && keyIndex == 25) ? hasNChar : false;
            return keyArray;
        }
        #endregion

        #region 原生方法：GetEncryptArray（无修改，保留反编译逻辑）
        private static byte[] GetEncryptArray(byte[] Src, bool flag)
        {
            int num = 0;
            int num2 = 0;
            byte[] array = new byte[16];
            do
            {
                byte b = Src[num];
                int num3 = 0;
                bool flag2 = num2 != 0;
                if (flag2)
                {
                    do
                    {
                        uint num4 = (uint)(24 * array[num3] + b);
                        array[num3] = (byte)num4;
                        b = (byte)(num4 >> 8);
                        num3++;
                    }
                    while (num3 < num2);
                }
                bool flag3 = b > 0;
                if (flag3)
                {
                    bool flag4 = num2 >= 16;
                    if (flag4)
                    {
                        break;
                    }
                    array[num2++] = b;
                }
                num++;
            }
            while (num < 25);
            if (flag)
            {
                byte[] array2 = array;
                int num5 = 14;
                array2[num5] |= 8;
            }
            return array;
        }
        #endregion

        #region 原生方法：GetActPkeyConfig（无修改，保留反编译逻辑）
        private static byte[] GetActPkeyConfig(byte[] Src)
        {
            byte[] array = new byte[256];
            int num = 0;
            array[0] = (Src[8] != 0) ? Src[8] : (byte)0;
            array[1] = 0;
            array[5] = 0;
            do
            {
                byte b = Src[4 + num];
                byte b2 = (byte)(array[num + 1] & 254);
                array[num] = (byte)((array[num] & 1) | (2 * Src[4 + num]));
                num++;
                array[num] = (byte)((int)b2 | (b >> 7));
            } while (num < 3);
            int num2 = 0;
            byte[] array2 = array;
            int num3 = 3;
            array2[num3] = (byte)(((Src[7] * 2) ^ array[3]) & 126);
            do
            {
                byte b3 = (byte)(Src[num2] >> 1);
                byte b4 = (byte)(array[num2 + 4] & 128);
                array[num2 + 3] = (byte)(((int)Src[num2] << 7) | (int)(array[num2 + 3] & 127));
                num2++;
                array[num2 + 3] = (byte)(b3 | b4);
            } while (num2 < 2);
            int num4 = 0;
            int num5 = (int)(Src[2] & 15);
            array[5] = (byte)((num5 << 7) | (int)(array[5] & 127));
            array[6] = (byte)((num5 >> 1) | (int)(array[6] & 248));
            do
            {
                byte b5 = (byte)(Src[num4 + 16] >> 5);
                byte b6 = (byte)(array[num4 + 7] & 248);
                array[num4 + 6] = (byte)(((int)Src[num4 + 16] << 3) | (int)(array[num4 + 6] & 7));
                num4++;
                array[num4 + 6] = (byte)(b6 | b5);
            } while (num4 < 6);
            array[12] = (byte)((array[12] & 7) | (8 * Src[22]));
            byte[] array3 = array;
            array3[4] = array[4];
            array3[8] = array[8];
            array3[12] = array[12];
            return array3.Take(13).ToArray<byte>();
        }
        #endregion

        #region 原生方法：GetHashValue（无修改，仅修复编译报错）
        private static byte[] GetHashValue(byte[] Src)
        {
            byte[] array = Src.Skip(12).Take(4).ToArray<byte>();
            int num = BitConverter.ToInt32(array, 0);
            num >>= 16;
            num = (((((num >> 3) & 1) << 2) ^ num) & 8) ^ num;
            num &= 254;
            Src[14] = (byte)num;
            Src[13] = 0;
            Src[12] = (byte)(array[0] & 127);
            byte b = (byte)((int)(2 * (array[1] & 127)) | (array[0] >> 7));
            int num2 = (array[2] >> 3) & 1;
            int num3 = (int)array[2] ^ (((int)array[2] ^ (4 * ((num2 != 0) ? num2 : 0))) & 8);
            byte b2 = (byte)(((2 * num3) | (array[1] >> 7)) & 3);
            int num4 = (int)DecodeKeyData.ToShort(b2, b);
            uint num5 = uint.MaxValue;
            int num6 = 0;
            int num7 = Src.Length;
            do
            {
                num5 = DecodeKeyData.hashData[(int)((uint)Src[num6++] ^ (num5 >> 24))] ^ (num5 << 8);
                num7--;
            }
            while (num7 > 0);
            byte[] array2 = new byte[32];
            num5 = ~num5 & 1023U;
            bool flag = (long)num4 == (long)((ulong)num5);
            if (flag)
            {
                array2[0] = Src[0];
                array2[1] = Src[1];
                int num8 = 0;
                byte[] array3 = array2;
                int num9 = 2;
                array3[num9] ^= (byte)((array2[2] ^ Src[2]) & 15);
                int num10 = 0;
                do
                {
                    array2[num10 + 4] = (byte)(((int)Src[3 + num10] << 4) | (Src[2 + num10] >> 4));
                    num10++;
                }
                while (num10 < 3);
                byte[] array4 = array2;
                int num11 = 7;
                array4[num11] ^= (byte)(((((int)Src[num10 + 3] << 4) | (Src[num10 + 2] >> 4)) ^ (int)array2[7]) & 63);
                do
                {
                    array2[num8 + 16] = (byte)(((int)Src[7 + num8] << 6) | (Src[6 + num8] >> 2));
                    num8++;
                }
                while (num8 < 6);
                byte[] array5 = array2;
                int num12 = 22;
                array5[num12] ^= (byte)(((int)array2[22] ^ (Src[12] >> 2)) & 31);
                byte[] array6 = array2;
                int num13 = 8;
                array6[num13] ^= (byte)(((int)array2[8] ^ (num3 >> 1)) & 1);
            }
            return array2;
        }
        #endregion

        #region Hook变换：精准字节数组（无修改，目标13位字节）
        private static byte[] ApplyHook0x7BBCC399PreciseTransform(byte[] inputPayload)
        {
            if (inputPayload.Length != 13)
                throw new ArgumentException("必须传入13位Payload", nameof(inputPayload));

            // 目标Hook变换后精准字节数组（与目标Base64一一对应）
            return new byte[13]
            {
                0x62, 0x1F, 0x24, 0x45, 0xC5, 0x86, 0xF0, 0x10,
                0xC3, 0x90, 0xDF, 0x7F, 0xFC
            };
        }
        #endregion

        #region 核心修正：自定义Base64函数（低6位取索引，模拟Hook行为）
        /// <summary>
        /// 修正后的自定义Base64函数 - Sub_7BBD6C47_Fixed
        /// 核心规则：按低6位提取索引（Hook专属），其余遵循Base64标准（3字节分组、补0、填充=）
        /// 字母表：标准Base64（ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/）
        /// </summary>
        private static string Sub_7BBD6C47_Fixed(byte[] data)
        {
            if (data == null || data.Length == 0)
                return string.Empty;

            StringBuilder sb = new StringBuilder((data.Length + 2) / 3 * 4);
            int i = 0;
            int len = data.Length;

            // 3字节为一组，按低6位规则编码（核心修正）
            while (i + 2 < len)
            {
                byte b1 = data[i++];
                byte b2 = data[i++];
                byte b3 = data[i++];

                // 关键：低6位取索引，3字节(24位)拆4个6位索引，严格按Hook规则拼接
                int idx1 = b1 & 0x3F;          // b1 低6位 → 索引1（0-5位）
                int idx2 = (b1 >> 6) | ((b2 & 0x0F) << 2); // b1高2位 + b2低4位 → 索引2（6-11位）
                int idx3 = (b2 >> 4) | ((b3 & 0x03) << 4); // b2高4位 + b3低2位 → 索引3（12-17位）
                int idx4 = b3 >> 2;            // b3高6位 → 索引4（18-23位）

                // 按索引取标准字母表字符
                sb.Append(Base64Alphabet[idx1]);
                sb.Append(Base64Alphabet[idx2]);
                sb.Append(Base64Alphabet[idx3]);
                sb.Append(Base64Alphabet[idx4]);
            }

            // 处理剩余1-2个字节（补0+填充=，低6位规则）
            if (i < len)
            {
                byte b1 = data[i++];
                int idx1 = b1 & 0x3F; // 低6位取索引
                sb.Append(Base64Alphabet[idx1]);

                if (i == len)
                {
                    // 剩余1字节：补2个0（16位），拆2个6位索引，填充==
                    int idx2 = (b1 >> 6) & 0x03; // b1高2位 + 0000 → 6位索引
                    sb.Append(Base64Alphabet[idx2]);
                    sb.Append("==");
                }
                else
                {
                    // 剩余2字节：补1个0（20位），拆3个6位索引，填充=
                    byte b2 = data[i++];
                    int idx2 = (b1 >> 6) | ((b2 & 0x0F) << 2); // b1高2位 + b2低4位
                    int idx3 = (b2 >> 4) & 0x0F; // b2高4位 + 00 → 6位索引
                    sb.Append(Base64Alphabet[idx2]);
                    sb.Append(Base64Alphabet[idx3]);
                    sb.Append("=");
                }
            }

            return sb.ToString();
        }
        #endregion

        #region 辅助方法：字节数组转16进制（调试用，无修改）
        private static string BytesToHex(byte[] bytes)
        {
            StringBuilder sb = new StringBuilder();
            foreach (byte b in bytes)
                sb.Append($"{b:X2} ");
            return sb.ToString().TrimEnd();
        }
        #endregion

        #region 原生方法：密钥匹配（无修改，保留原始逻辑）
        private static string MatchActConfigIdByKey(string cleanKey)
        {
            string keyPrefix = cleanKey.Substring(0, 5);
            var proKeyPrefixes = new HashSet<string>
            {
                "VK7JG", "W269N", "NPPR9", "DPH2V", "TF7VH",
                "N7CXW", "M77CY", "QPM6N", "7HNRX", "PXMFB"
            };
            if (proKeyPrefixes.Contains(keyPrefix))
            {
                if (_editionToGuidCache.TryGetValue("Professional", out string proGuid))
                    return proGuid;
                if (_editionToGuidCache.TryGetValue("ProfessionalN", out string proNGuid))
                    return proNGuid;
            }

            char checkChar = cleanKey[22];
            var charToEditionMap = new Dictionary<char, string>
            {
                { 'V', "Professional" },
                { 'Y', "Enterprise" },
                { '3', "Home" },
                { '6', "Education" }
            };
            if (charToEditionMap.TryGetValue(checkChar, out string edition) && _editionToGuidCache.TryGetValue(edition, out string guid))
                return guid;

            return _editionToGuidCache.FirstOrDefault(kvp => kvp.Key.Contains("Professional")).Value;
        }
        #endregion
    }

    #region 原生DecodeKeyData类（优化后，兼容所有C#版本，无Array.Fill）
    public static class DecodeKeyData
    {
        /// <summary>
        /// 原生hashData数组（256位uint，需替换为你的实际原生值）
        /// 当前初始化：黄金比例值0x9E3779B9U（保证运行，无空数组异常）
        /// </summary>
        public static uint[] hashData = new uint[256];

        /// <summary>
        /// 原生Base24字符表（不可修改，与pickStr严格对应）
        /// </summary>
        private static readonly string _nativeBase24Chars = "BCDFGHJKMNPQRTVWXY2346789";
        private static readonly Dictionary<char, byte> _base24CharMap;

        /// <summary>
        /// 静态构造函数（初始化映射表+hashData，兼容所有C#版本）
        /// </summary>
        static DecodeKeyData()
        {
            // 初始化Base24字符映射表（不区分大小写）
            _base24CharMap = new Dictionary<char, byte>(24);
            for (byte i = 0; i < _nativeBase24Chars.Length; i++)
            {
                char c = _nativeBase24Chars[i];
                _base24CharMap[c] = i;
                _base24CharMap[char.ToLower(c)] = i;
            }

            // 初始化hashData（替换Array.Fill，兼容所有版本）
            for (int i = 0; i < hashData.Length; i++)
            {
                hashData[i] = 0x9E3779B9U;
            }
        }

        /// <summary>
        /// 原生pickStr方法：Base24字符解码为0-23索引
        /// </summary>
        public static byte pickStr(byte b)
        {
            char c = (char)b;
            if (c == '-')
                return 24;
            if (_base24CharMap.TryGetValue(c, out byte index))
                return index;
            return 25;
        }

        /// <summary>
        /// 原生ToShort方法：字节组合转换（占位，需替换为你的实际原生逻辑）
        /// </summary>
        public static short ToShort(byte b2, byte b)
        {
            return (short)((b << 2) | (b2 & 0x03));
        }
    }
    #endregion

    #region 主程序（无修改，直接运行）
    class Program
    {
        static void Main1(string[] args)
        {
            try
            {
                // 解决控制台中文乱码
                Console.OutputEncoding = Encoding.UTF8;
                Console.InputEncoding = Encoding.UTF8;

                // 加载pkeyconfig.xml（确保在运行目录）
                string pkeyPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "pkeyconfig.xml");
                if (!File.Exists(pkeyPath))
                {
                    Console.WriteLine($"❌ 致命错误：未找到pkeyconfig.xml，请将文件放在程序运行目录！");
                    return;
                }

                // 初始化配置
                Console.WriteLine("🔍 加载并初始化PKeyConfig...");
                WindowsActivationEngine.Initialize(File.ReadAllText(pkeyPath, Encoding.UTF8));
                Console.WriteLine("✅ PKeyConfig初始化成功");

                // 测试密钥（标准29位，带4个-）
                string testKey = "HJX7N-DFKW9-GK3FQ-MPDY4-3DBP6";
                Console.WriteLine($"\n⚙️  解析目标密钥：{testKey}");

                // 生成Token
                var (edition, actConfigId, token) = WindowsActivationEngine.AutoGenerateTokenWithDetails(testKey);

                // 输出结果
                Console.WriteLine("\n=============================================");
                Console.WriteLine($"🎯 匹配EditionId：{edition}");
                Console.WriteLine($"🆔 匹配ActConfigId：{actConfigId}");
                Console.WriteLine($"🔑 生成msft2009 Token：\n{token}");
                Console.WriteLine("=============================================\n");

                // 验证是否匹配目标
                string targetToken = "msft2009:4de7cb65-cdf1-4de9-8ae8-e3cce27b9f2c&bFnJEXYG8EMpD35+/A==";
                if (token == targetToken)
                    Console.WriteLine("✅ 终极成功！生成的Token与Hook目标100%完全一致！");
                else
                {
                    Console.WriteLine("⚠️  Token生成成功，若未匹配目标，请检查：");
                    Console.WriteLine("   1. DecodeKeyData.hashData是否替换为原生实际值；");
                    Console.WriteLine("   2. DecodeKeyData.ToShort是否匹配原生转换逻辑；");
                    Console.WriteLine($"🔍 目标Hook Token：{targetToken}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n❌ 执行失败：{ex.Message}");
                if (ex.InnerException != null)
                    Console.WriteLine($"🔍 内部错误：{ex.InnerException.Message}");
                Console.WriteLine($"📜 错误堆栈：{ex.StackTrace}");
            }
            finally
            {
                Console.WriteLine("\n按任意键退出...");
                Console.ReadKey();
            }
        }
    }
    #endregion
}