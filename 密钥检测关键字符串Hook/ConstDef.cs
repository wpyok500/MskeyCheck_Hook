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
            bool isNKey = false;
            // 第一步：获取密钥索引
            byte[] keyArray = GetKeyArray(productKey, ref isNKey);
            // 第二步：关键！转换为 16 字节原始数据 (之前漏掉了这一步)
            byte[] encryptedArray = GetEncryptArray(keyArray, isNKey);
            // 第三步：计算 CRC/Hash 映射
            byte[] hashBuffer = GetHashValue(encryptedArray);
            // 第四步：映射为 13 字节 Payload
            return GetActPkeyConfig(hashBuffer);
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
            if (flag) array[14] |= 8; // N-Key 特殊标记
            return array;
        }
        #endregion

        #region 核心逻辑：Hash 计算 (GetHashValue)
        private static byte[] GetHashValue(byte[] Src)
        {
            // 原始 CRC 逻辑
            uint crc = uint.MaxValue;
            foreach (byte b in Src)
                crc = HashData[(int)((uint)b ^ (crc >> 24))] ^ (crc << 8);

            byte[] res = new byte[32];

            // 这里的 Src 应该是 GetEncryptArray 返回的 16 字节
            // SPP 实际上是将这 16 字节重新排列到 32 字节缓冲区中
            for (int i = 0; i < 16; i++)
            {
                res[i] = Src[i];
            }

            // 关键混淆区：res[16..22] 承载了密钥的核心 Hash 特征
            // 我们微调一下位移偏量
            res[16] = (byte)((Src[6] >> 2) | (Src[7] << 6));
            res[17] = (byte)((Src[7] >> 2) | (Src[8] << 6));
            res[18] = (byte)((Src[8] >> 2) | (Src[9] << 6));
            res[19] = (byte)((Src[9] >> 2) | (Src[10] << 6));
            res[20] = (byte)((Src[10] >> 2) | (Src[11] << 6));
            res[21] = (byte)((Src[11] >> 2) | (Src[12] << 6));
            res[22] = (byte)(Src[12] >> 2);

            res[8] = 1; // 激活标记
            return res;
        }
        #endregion

        #region 核心逻辑：Payload 转换 (GetActPkeyConfig)
        private static byte[] GetActPkeyConfig(byte[] Src)
        {
            byte[] array = new byte[13];

            // 核心修正：严格遵循位流偏移。
            // 如果结果依然为 7Xit，说明 Src 数组的输入源（GetHashValue）中的索引需要前移或后移

            // 0-7 bits: [Src8:bit0] + [Src4:7bits]
            array[0] = (byte)((Src[8] & 1) | ((Src[4] & 0x7F) << 1));

            // 8-15 bits: [Src4:bit7] + [Src5:7bits]
            array[1] = (byte)(((Src[4] >> 7) & 1) | ((Src[5] & 0x7F) << 1));

            // 16-23 bits: [Src5:bit7] + [Src6:7bits]
            array[2] = (byte)(((Src[5] >> 7) & 1) | ((Src[6] & 0x7F) << 1));

            // 24-31 bits: [Src6:bit7] + [Src7:7bits]
            // 关键：注意 Src[0] 是否应该在此处介入
            array[3] = (byte)(((Src[6] >> 7) & 1) | (Src[7] << 1));

            // 后续字节处理，确保 Src[16-22] 准确对齐
            array[4] = Src[0];
            array[5] = Src[1];
            array[6] = (byte)((Src[2] & 0x1F) | (Src[16] << 5));
            array[7] = (byte)((Src[16] >> 3) | (Src[17] << 5));
            array[8] = (byte)((Src[17] >> 3) | (Src[18] << 5));
            array[9] = (byte)((Src[18] >> 3) | (Src[19] << 5));
            array[10] = (byte)((Src[19] >> 3) | (Src[20] << 5));
            array[11] = (byte)((Src[20] >> 3) | (Src[21] << 5));
            array[12] = (byte)((Src[21] >> 3) | (Src[22] << 5));

            return array;
        }

        private static string Sub_7BBD6C47_Fixed(byte[] data)
        {
            // 强制 Hook 特征：首字节低两位置 1 (即 +3)
            data[0] |= 0x03;

            StringBuilder sb = new StringBuilder();
            // 这里必须使用“位流读取”模式：从第一个字节开始，每次取 6 位，但不跨越字节序边界
            for (int i = 0; i < data.Length; i += 3)
            {
                uint block = (uint)data[i];
                if (i + 1 < data.Length) block |= (uint)data[i + 1] << 8;
                if (i + 2 < data.Length) block |= (uint)data[i + 2] << 16;

                for (int j = 0; j < 4; j++)
                {
                    if (sb.Length < 18)
                    {
                        sb.Append(Base64Alphabet[(int)(block & 0x3F)]);
                        block >>= 6;
                    }
                }
            }

            return sb.ToString().Substring(0, 18) + "==";
        }
        #endregion

        private static byte pickStr(byte str)
        {
            string valid = "BCDFGHJKMNPQRTVWXY2346789";
            if (str == 45) return 24;
            int idx = valid.IndexOf(char.ToUpper((char)str));
            return idx != -1 ? (byte)idx : (byte)25;
        }
    }
    
}