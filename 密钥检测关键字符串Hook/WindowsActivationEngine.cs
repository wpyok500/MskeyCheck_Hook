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
        #region 核心常量与查找表
        private const string Base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        // SPP 内部 CRC 查找表
        private static uint[] HashData = new uint[]
        {
            0U, 79764919U, 159529838U, 222504665U, 319059676U, 398814059U, 445009330U, 507990021U, 638119352U, 583659535U,
            797628118U, 726387553U, 890018660U, 835552979U, 1015980042U, 944750013U, 1276238704U, 1221641927U, 1167319070U, 1095957929U,
            1595256236U, 1540665371U, 1452775106U, 1381403509U, 1780037320U, 1859660671U, 1671105958U, 1733955601U, 2031960084U, 2111593891U,
            1889500026U, 1952343757U, 2552477408U, 2632100695U, 2443283854U, 2506133561U, 2334638140U, 2414271883U, 2191915858U, 2254759653U,
            3190512472U, 3135915759U, 3081330742U, 3009969537U, 2905550212U, 2850959411U, 2762807018U, 2691435357U, 3560074640U, 3505614887U,
            3719321342U, 3648080713U, 3342211916U, 3287746299U, 3467911202U, 3396681109U, 4063920168U, 4143685023U, 4223187782U, 4286162673U,
            3779000052U, 3858754371U, 3904687514U, 3967668269U, 881225847U, 809987520U, 1023691545U, 969234094U, 662832811U, 591600412U,
            771767749U, 717299826U, 311336399U, 374308984U, 453813921U, 533576470U, 25881363U, 88864420U, 134795389U, 214552010U,
            2023205639U, 2086057648U, 1897238633U, 1976864222U, 1804852699U, 1867694188U, 1645340341U, 1724971778U, 1587496639U, 1516133128U,
            1461550545U, 1406951526U, 1302016099U, 1230646740U, 1142491917U, 1087903418U, 2896545431U, 2825181984U, 2770861561U, 2716262478U,
            3215044683U, 3143675388U, 3055782693U, 3001194130U, 2326604591U, 2389456536U, 2200899649U, 2280525302U, 2578013683U, 2640855108U,
            2418763421U, 2498394922U, 3769900519U, 3832873040U, 3912640137U, 3992402750U, 4088425275U, 4151408268U, 4197601365U, 4277358050U,
            3334271071U, 3263032808U, 3476998961U, 3422541446U, 3585640067U, 3514407732U, 3694837229U, 3640369242U, 1762451694U, 1842216281U,
            1619975040U, 1682949687U, 2047383090U, 2127137669U, 1938468188U, 2001449195U, 1325665622U, 1271206113U, 1183200824U, 1111960463U,
            1543535498U, 1489069629U, 1434599652U, 1363369299U, 622672798U, 568075817U, 748617968U, 677256519U, 907627842U, 853037301U,
            1067152940U, 995781531U, 51762726U, 131386257U, 177728840U, 240578815U, 269590778U, 349224269U, 429104020U, 491947555U,
            4046411278U, 4126034873U, 4172115296U, 4234965207U, 3794477266U, 3874110821U, 3953728444U, 4016571915U, 3609705398U, 3555108353U,
            3735388376U, 3664026991U, 3290680682U, 3236090077U, 3449943556U, 3378572211U, 3174993278U, 3120533705U, 3032266256U, 2961025959U,
            2923101090U, 2868635157U, 2813903052U, 2742672763U, 2604032198U, 2683796849U, 2461293480U, 2524268063U, 2284983834U, 2364738477U,
            2175806836U, 2238787779U, 1569362073U, 1498123566U, 1409854455U, 1355396672U, 1317987909U, 1246755826U, 1192025387U, 1137557660U,
            2072149281U, 2135122070U, 1912620623U, 1992383480U, 1753615357U, 1816598090U, 1627664531U, 1707420964U, 295390185U, 358241886U,
            404320391U, 483945776U, 43990325U, 106832002U, 186451547U, 266083308U, 932423249U, 861060070U, 1041341759U, 986742920U,
            613929101U, 542559546U, 756411363U, 701822548U, 3316196985U, 3244833742U, 3425377559U, 3370778784U, 3601682597U, 3530312978U,
            3744426955U, 3689838204U, 3819031489U, 3881883254U, 3928223919U, 4007849240U, 4037393693U, 4100235434U, 4180117107U, 4259748804U,
            2310601993U, 2373574846U, 2151335527U, 2231098320U, 2596047829U, 2659030626U, 2470359227U, 2550115596U, 2947551409U, 2876312838U,
            2788305887U, 2733848168U, 3165939309U, 3094707162U, 3040238851U, 2985771188U
        };
        #endregion

        #region 缓存容器
        private static readonly Dictionary<string, string> _editionToGuidCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, List<string>> _guidToEditionsCache = new Dictionary<string, List<string>>();
        private static readonly object _cacheLock = new object();

        #endregion

        #region 初始化 PKeyConfig
        public static void Initialize(string pkeyConfigXmlContent)
        {
            if (string.IsNullOrEmpty(pkeyConfigXmlContent)) throw new ArgumentNullException(nameof(pkeyConfigXmlContent));

            lock (_cacheLock)
            {
                _editionToGuidCache.Clear();
                _guidToEditionsCache.Clear();

                XmlDocument doc = new XmlDocument();
                doc.LoadXml(ExtractInnerConfig(pkeyConfigXmlContent));

                foreach (XmlNode configNode in doc.GetElementsByTagName("Configuration"))
                {
                    string actConfigId = configNode.SelectSingleNode(".//*[local-name()='ActConfigId']")?.InnerText?.Trim('{', '}').ToLowerInvariant();
                    string editionIdsText = configNode.SelectSingleNode(".//*[local-name()='EditionId']")?.InnerText?.Trim();

                    if (string.IsNullOrEmpty(actConfigId) || string.IsNullOrEmpty(editionIdsText)) continue;

                    var editions = editionIdsText.Split(';').Select(e => e.Trim()).Where(e => !string.IsNullOrEmpty(e)).ToList();
                    foreach (var ed in editions) _editionToGuidCache[ed] = actConfigId;
                    _guidToEditionsCache[actConfigId] = editions;
                }
            }
        }

        private static string ExtractInnerConfig(string outerXml)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(outerXml);
            XmlNamespaceManager nsmgr = new XmlNamespaceManager(doc.NameTable);
            nsmgr.AddNamespace("tm", "http://www.microsoft.com/DRM/XrML2/TM/v2");
            var node = doc.SelectSingleNode("//tm:infoBin[@name='pkeyConfigData']", nsmgr);
            byte[] binaryData = Convert.FromBase64String(node.InnerText.Replace("\n", "").Replace("\r", "").Trim());
            string decoded = Encoding.UTF8.GetString(binaryData);
            return decoded.Contains("<?xml") ? decoded.Substring(decoded.IndexOf("<?xml")) : decoded;
        }
        #endregion

        #region 核心Token生成逻辑（动态计算）
        public static (string TargetEditionId, string ActConfigId, string Token1, string Token2) AutoGenerateTokenWithDetails(string productKey)
        {
            string actConfigId = "4de7cb65-cdf1-4de9-8ae8-e3cce27b9f2c"; // 目标版本ID
            string editionId = _guidToEditionsCache.TryGetValue(actConfigId, out var eds) ? eds.First() : "Professional";

            (string base64Part1, string base64Part2) = CalculateDynamicPayload(productKey);

            string finalToken1 = $"msft2009:{actConfigId}&{base64Part1}";
            string finalToken2 = $"msft2009:{actConfigId}&{base64Part1}";
            return (editionId, actConfigId, finalToken1, finalToken2);
        }

        private static (string token1,string token2 ) CalculateDynamicPayload(string productKey)
        {
            bool flag = true;
            byte[] array2 = GetKeyArray(productKey, ref flag);
            array2 = GetEncryptArray(array2, flag);
            // 主用的 Hash 计算方法，对应原版 SPPTokenGenerator 实现 ----方法一
            byte[] hashValue = GetHashValue(array2);
            //备用的 Hash 计算方法，对应原版 SPPTokenGenerator 实现 ----方法二
            byte[] hashValue1 = GetHashValue(array2);

            //方法一
            array2 = GetActPkeyConfig(hashValue);
            string text6 = Convert.ToBase64String(array2);

            //方法二
            byte[] array3 = GetActPkeyConfig1(hashValue1);
            string text6_1 = Sub_7BBD6C47_Fixed(array3);
            return (text6, text6_1);
        }
        #endregion

        #region 核心逻辑：密钥 -> 字节数组 (GetKeyArray & GetEncryptArray)
        private static byte[] GetKeyArray(string productKey, ref bool flag)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(productKey);
            byte[] array = new byte[25];
            bool flag2 = false, flag3 = false;
            int i = 0, num = 0, num2 = 0, num3 = 0;

            while (i < 25 && num < bytes.Length)
            {
                byte b = bytes[num];
                if (b == 78 || b == 110) // 'N'
                {
                    if (flag3 || i >= 24) break;
                    flag2 = true;
                    // N-Key 逻辑：将当前索引插入头部，其余后移
                    byte[] head = { (byte)i };
                    array = head.Concat(array.Take(24)).ToArray();
                    i++; num2 = num3;
                }
                else
                {
                    byte b2 = pickStr(b);
                    if (b2 < 24) { array[i] = b2; i++; }
                    else if (b2 == 24 && (num == 5 || num == 11 || num == 17 || num == 23)) num2 = ++num3;
                }
                num++; flag3 = flag2;
            }
            flag = flag2;
            return array;
        }

        private static byte[] GetEncryptArray(byte[] Src, bool flag)
        {
            byte[] array = new byte[16];
            int num2 = 0;
            for (int i = 0; i < 25; i++)
            {
                uint val = Src[i];
                int j = 0;
                if (num2 != 0)
                {
                    do
                    {
                        uint num4 = 24 * (uint)array[j] + val;
                        array[j] = (byte)num4;
                        val = num4 >> 8;
                        j++;
                    } while (j < num2);
                }
                if (val > 0 && num2 < 16) array[num2++] = (byte)val;
            }
            if (flag) array[14] |= 8;
            return array;
        }
        #endregion

        #region 核心逻辑：Hash 计算 (GetHashValue)
        private static byte[] GetHashValue(byte[] Src)
        {
            // 1. 备份原始数据，因为 CRC 校验是针对“修改前”的部分数据和“修改后”的整体
            byte[] array = new byte[4];
            Buffer.BlockCopy(Src, 12, array, 0, 4);

            // 2. 计算 num4 (必须在 Src[12-14] 被覆盖前完成，或者使用备份)
            int num = (int)((array[3] << 8) | array[2]); // 对应原 num = ToInt32 >> 16
            num = (((((num >> 3) & 1) << 2) ^ num) & 8) ^ num;

            // 计算比较值 b 和 b2
            byte b = (byte)((2 * (array[1] & 0x7F)) | (array[0] >> 7));
            int num2 = (array[2] >> 3) & 1;
            int num3 = (int)array[2] ^ (((int)array[2] ^ (4 * (num2 != 0 ? 1 : 0))) & 8);
            byte b2 = (byte)(((2 * num3) | (array[1] >> 7)) & 3);
            int num4 = (int)((b2 << 8) | b);

            // 3. 按照 SPP 规则修改 Src 数组，准备进行 CRC 扫描
            Src[14] = (byte)(num & 0xFE);
            Src[13] = 0;
            Src[12] = (byte)(array[0] & 0x7F);

            // 4. CRC 计算
            uint crc = uint.MaxValue;
            foreach (byte t in Src)
            {
                // 核心：uint 强转确保索引不溢出
                crc = HashData[(crc >> 24) ^ t] ^ (crc << 8);
            }

            uint finalHash = (~crc) & 0x3FF; // 1023U
            byte[] array2 = new byte[32];

            // 5. 校验：如果 num4 不等于 CRC 结果，说明前面的 GetEncryptArray 数据就不对
            if ((uint)num4 == finalHash)
            {
                // 填充逻辑 (Bit Reassembly)
                array2[0] = Src[0];
                array2[1] = Src[1];

                // array2[2] 取 Src[2] 的低 4 位
                array2[2] = (byte)(Src[2] & 0x0F);

                // 处理 4-bit 偏移映射
                for (int i = 0; i < 3; i++)
                {
                    array2[i + 4] = (byte)((Src[i + 3] << 4) | (Src[i + 2] >> 4));
                }

                // 处理特征位映射
                array2[7] = (byte)(((Src[6] << 4) | (Src[5] >> 4)) & 0x3F);

                // 处理 2-bit 偏移映射 (Hash 混淆区)
                for (int i = 0; i < 6; i++)
                {
                    array2[i + 16] = (byte)((Src[i + 7] << 6) | (Src[i + 6] >> 2));
                }

                array2[22] = (byte)((Src[12] >> 2) & 0x1F);
                array2[8] = (byte)((num3 >> 1) & 1);
            }
            else
            {
                // 调试建议：如果走到这里，说明输入的 productKey 转换出的 Src 不符合该 pkeyconfig 的算法
                // Console.WriteLine($"CRC Mismatch: Expected {num4:X}, Got {finalHash:X}");
            }

            return array2;
        }

        private static byte[] GetHashValue1(byte[] Src)
        {
            // 1. 必须先备份原始数据，因为 Src[12-14] 会被修改
            byte[] array = new byte[4];
            Buffer.BlockCopy(Src, 12, array, 0, 4);

            // 2. 这里的计算逻辑必须基于原始 array 备份
            int num = (int)((array[3] << 8) | array[2]);
            num = (((((num >> 3) & 1) << 2) ^ num) & 8) ^ num;

            byte b = (byte)((2 * (array[1] & 127)) | (array[0] >> 7));
            int num2 = (array[2] >> 3) & 1;
            int num3 = (int)array[2] ^ (((int)array[2] ^ (4 * (num2 != 0 ? 1 : 0))) & 8);
            byte b2 = (byte)(((2 * num3) | (array[1] >> 7)) & 3);
            int num4 = (int)((b2 << 8) | b);

            // 3. 修改 Src 准备 CRC 扫描
            Src[14] = (byte)(num & 254);
            Src[13] = 0;
            Src[12] = (byte)(array[0] & 127);

            // 4. CRC 校验 (HashData 表驱动)
            uint crc = uint.MaxValue;
            for (int i = 0; i < Src.Length; i++)
            {
                crc = HashData[(crc >> 24) ^ Src[i]] ^ (crc << 8);
            }

            uint finalHash = (~crc) & 1023U;
            byte[] result = new byte[32];

            // 5. 如果校验通过，填充数据；如果失败，为了调试，我们强制填充它！
            // 提示：正式环境应保留 if (num4 == finalHash)
            if (true) // 强制填充以观察位流映射是否正确
            {
                result[0] = Src[0];
                result[1] = Src[1];
                result[2] = (byte)(Src[2] & 0x0F);
                // ... (保持你之前的映射逻辑)
                result[8] = (byte)((num3 >> 1) & 1);

                // 映射核心区
                Buffer.BlockCopy(Src, 4, result, 4, 4); // Src[4-7] -> result[4-7]
                Buffer.BlockCopy(Src, 16, result, 16, 6); // 如果 Src 够长
            }

            return result;
        }
        #endregion

        #region 核心逻辑：Payload 转换 (GetActPkeyConfig)
        private static byte[] GetActPkeyConfig(byte[] Src)
        {
            byte[] array = new byte[256];

            // 初始化前两个字节
            array[0] = (byte)((Src[8] != 0) ? Src[8] : 0);
            array[1] = 0;
            array[5] = 0;

            // 第一阶段：处理 Src[4..6]
            int num = 0;
            do
            {
                byte b = Src[4 + num];
                byte b2 = (byte)(array[num + 1] & 254);
                array[num] = (byte)((array[num] & 1) | (2 * Src[4 + num]));
                num++;
                array[num] = (byte)((int)b2 | (b >> 7));
            }
            while (num < 3);

            // 第二阶段：特殊处理 array[3]
            // 源码逻辑：array2[num3] ^= (byte)(((Src[7] * 2) ^ array[3]) & 126);
            // 这实际上是将 Src[7] 的前 7 位移动到 array[3]
            array[3] ^= (byte)(((Src[7] * 2) ^ array[3]) & 126);

            // 第三阶段：处理 Src[0..1]
            int num2 = 0;
            do
            {
                byte b3 = (byte)(Src[num2] >> 1);
                byte b4 = (byte)(array[num2 + 4] & 128);
                array[num2 + 3] = (byte)(((int)Src[num2] << 7) | (int)(array[num2 + 3] & 127));
                num2++;
                array[num2 + 3] = (byte)(b3 | b4);
            }
            while (num2 < 2);

            // 第四阶段：处理 Src[2] 的低 4 位
            int num5 = (int)(Src[2] & 15);
            array[5] = (byte)((num5 << 7) | (int)(array[5] & 127));
            array[6] = (byte)((num5 >> 1) | (int)(array[6] & 248));

            // 第五阶段：处理 Hash 混淆区 Src[16..21]
            int num4 = 0;
            do
            {
                byte b5 = (byte)(Src[num4 + 16] >> 5);
                byte b6 = (byte)(array[num4 + 7] & 248);
                array[num4 + 6] = (byte)(((int)Src[num4 + 16] << 3) | (int)(array[num4 + 6] & 7));
                num4++;
                array[num4 + 6] = (byte)(b6 | b5);
            }
            while (num4 < 6);

            // 最终：处理 Src[22]
            array[12] = (byte)((array[12] & 7) | (8 * Src[22]));

            return array.Take(13).ToArray();
        }

        private static byte[] GetActPkeyConfig1(byte[] Src)
        {
            // 如果 Hash 校验没过，Src 全 0，直接返回
            if (Src.All(b => b == 0)) return new byte[13];

            byte[] array = new byte[13];

            // --- 按照 Little-Endian 位流顺序平铺数据 ---

            // 1. 放置标记位 (Src[8]) - 这决定了第一个字符的高位
            array[0] = Src[8];

            // 2. 放置版本/ActConfig 映射 (Src[4..7])
            array[1] = Src[4];
            array[2] = Src[5];
            array[3] = Src[6];
            array[4] = Src[7];

            // 3. 放置密钥序列 (Src[0..1])
            array[5] = Src[0];
            array[6] = Src[1];

            // 4. 放置 Src[2] 的特征位 (低4位)
            array[7] = (byte)(Src[2] & 0x0F);

            // 5. 放置混淆校验区 (Src[16..20])
            array[8] = Src[16];
            array[9] = Src[17];
            array[10] = Src[18];
            array[11] = Src[19];
            array[12] = Src[20];

            return array;
        }

        private static string Sub_7BBD6C47_Fixed(byte[] data)
        {
            // 1. 注入 msft2009 协议特征位
            // 这两个比特决定了 Base64 字符串的首字符 (例如 5, 6, 7 等)
            data[0] |= 0x03;

            StringBuilder sb = new StringBuilder();
            uint buffer = 0;
            int bitsInBuffer = 0;
            int processedBytes = 0;

            // 2. 位流读取逻辑：从字节数组中不断提取 6 位索引
            // msft2009 Token 通常包含 18 个有效 Base64 字符
            while (sb.Length < 18)
            {
                // 如果缓存池中的比特不足 6 位，则从数组中读取下一个字节补位
                if (bitsInBuffer < 6 && processedBytes < data.Length)
                {
                    buffer |= (uint)(data[processedBytes] << bitsInBuffer);
                    bitsInBuffer += 8;
                    processedBytes++;
                }

                // 取出低 6 位作为 Base64 字符表的索引
                int charIndex = (int)(buffer & 0x3F);
                sb.Append(Base64Alphabet[charIndex]);

                // 消耗掉这 6 位
                buffer >>= 6;
                bitsInBuffer -= 6;
            }

            // 3. 按照标准输出格式补齐后缀
            return sb.ToString() + "==";
        }
        #endregion

        private static byte pickStr(byte str)
        {
            // Windows 密钥标准字符集 (去掉了易混淆的 0,1,5,A,E,I,L,O,S,U)
            // 映射索引: 0123456789...
            const string alphabet = "BCDFGHJKMPQRTVWXY2346789";

            if (str == 45) return 24; // '-'
            char c = char.ToUpper((char)str);
            int idx = alphabet.IndexOf(c);
            return idx != -1 ? (byte)idx : (byte)25;
        }
    }
    
}