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
        private static readonly uint[] HashData = new uint[] {
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
        public static (string TargetEditionId, string ActConfigId, string Token) AutoGenerateTokenWithDetails(string productKey)
        {
            string actConfigId = "4de7cb65-cdf1-4de9-8ae8-e3cce27b9f2c"; // 目标版本ID
            string editionId = _guidToEditionsCache.TryGetValue(actConfigId, out var eds) ? eds.First() : "Professional";

            // 1. 关键：将密钥计算为 13 字节的动态 Payload (匹配截图中的 array2)
            byte[] dynamicPayload = CalculateDynamicPayload(productKey);

            // 2. 将计算结果进行 Base64 编码 (含位移修正)
            string base64Part = Sub_7BBD6C47_Fixed(dynamicPayload);

            string finalToken = $"msft2009:{actConfigId}&{base64Part}";
            return (editionId, actConfigId, finalToken);
        }

        private static byte[] CalculateDynamicPayload(string productKey)
        {
            bool flag = true;
            byte[] keyArray = GetKeyArray(productKey, ref flag);
            byte[] hashBuffer = GetHashValue(keyArray);
            return GetActPkeyConfig(hashBuffer);
        }
        #endregion

        #region 算法：GetKeyArray / GetHashValue / GetActPkeyConfig
        private static byte[] GetKeyArray(string productKey, ref bool flag)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(productKey);
            byte[] array = new byte[25];
            bool f2 = false; bool f3 = false;
            int i = 0, num = 0, num2 = 0, num3 = 0;
            while (i < 25 && num < bytes.Length)
            {
                byte b = bytes[num];
                if (b == 78 || b == 110)
                { // 'N'
                    if (f3 || i >= 24) break;
                    f2 = true;
                    array = BitConverter.GetBytes(i).Take(1).Concat(array.Take(24)).ToArray();
                    i++; num2 = num3;
                }
                else
                {
                    byte b2 = DecodeKeyData.pickStr(b);
                    if (b2 < 24) { array[i] = b2; i++; }
                    else if (b2 == 24 && num2 < 4) num2 = ++num3;
                }
                num++; f3 = f2;
            }
            return array;
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



        #region 核心：全动态位映射算法 (匹配 0x04D5C399 逻辑)
        private static byte[] GetActPkeyConfig(byte[] Src)
        {
            byte[] res = new byte[13];

            // 初始化 res[0]
            res[0] = (byte)(Src[8] != 0 ? Src[8] : 0);

            // 映射 Src[4..6] 到 res[0..3]
            int num = 0;
            do
            {
                byte b = Src[4 + num];
                res[num] = (byte)((res[num] & 1) | (byte)(2 * Src[4 + num]));
                num++;
                if (num < 13) res[num] = (byte)((res[num] & 254) | (byte)(b >> 7));
            } while (num < 3);

            // 映射 Src[7] 到 res[3]
            res[3] ^= (byte)(((Src[7] * 2) ^ res[3]) & 126);

            // 映射 Src[0..1] 到 res[3..5]
            for (int j = 0; j < 2; j++)
            {
                byte b3 = (byte)(Src[j] >> 1);
                res[j + 3] = (byte)(((int)Src[j] << 7) | (res[j + 3] & 127));
                if (j + 4 < 13) res[j + 4] = (byte)(b3 | (res[j + 4] & 128));
            }

            // 映射 Src[2] (低4位) 到 res[5..6]
            int valLow4 = (int)(Src[2] & 15);
            res[5] = (byte)((valLow4 << 7) | (res[5] & 127));
            res[6] = (byte)((valLow4 >> 1) | (res[6] & 248));

            // 映射 Src[16..21] 到 res[6..12]
            for (int k = 0; k < 6; k++)
            {
                byte b5 = (byte)(Src[k + 16] >> 5);
                res[k + 6] = (byte)(((int)Src[k + 16] << 3) | (res[k + 6] & 7));
                if (k + 7 < 13) res[k + 7] = (byte)((res[k + 7] & 248) | b5);
            }

            // 映射 Src[22] 到 res[12]
            res[12] = (byte)((res[12] & 7) | (byte)(8 * Src[22]));

            return res;
        }
        #endregion

        #region 密钥哈希计算 (0x04D5A9CB 逻辑)
        private static byte[] GetHashValue(byte[] Src)
        {
            // 复制 Src 的 12..15 字节进行校验计算
            byte[] checkPart = Src.Skip(12).Take(4).ToArray();
            uint val = BitConverter.ToUInt32(checkPart, 0);

            // 模拟原代码中的位混乱逻辑，确保 Checksum 通过
            // 注意：Src 在此会被原地修改，这符合反编译源码的行为
            Src[13] = 0;
            Src[12] &= 127;

            uint crc = uint.MaxValue;
            foreach (byte b in Src)
                crc = HashData[(int)(b ^ (crc >> 24))] ^ (crc << 8);

            byte[] buffer = new byte[32];
            // 模拟反编译中 array2 的填充逻辑
            buffer[0] = Src[0];
            buffer[1] = Src[1];
            buffer[2] = (byte)(Src[2] & 15); // 对应原代码中的 (array2[2] ^ Src[2]) & 15

            for (int i = 0; i < 3; i++)
                buffer[i + 4] = (byte)((Src[i + 3] << 4) | (Src[i + 2] >> 4));

            for (int i = 0; i < 6; i++)
                buffer[i + 16] = (byte)((Src[i + 7] << 6) | (Src[i + 6] >> 2));

            buffer[22] = (byte)(Src[12] >> 2);
            buffer[8] = 1; // 激活标志位

            return buffer;
        }
        #endregion
    }

    public static class DecodeKeyData
    {
        public static byte pickStr(byte b)
        {
            string valid = "BCDFGHJKMNPQRTVWXY2346789";
            if (b == '-') return 24;
            int idx = valid.IndexOf(char.ToUpper((char)b));
            return idx != -1 ? (byte)idx : (byte)25;
        }
    }
    
}