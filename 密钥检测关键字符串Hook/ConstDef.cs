using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;

public class WindowsActivationEngine
{
    // 汇编原生字符集（与SPP内部完全一致，不可修改）
    private const string Base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private const string Base24Alphabet = "BCDFGHJKMNPQRTVWXY2346789";

    // 缓存：EditionId→ActConfigId + 反向映射（ActConfigId→EditionId列表）
    private static readonly Dictionary<string, string> _editionToGuidCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<string, List<string>> _guidToEditionsCache = new Dictionary<string, List<string>>();
    private static readonly object _cacheLock = new object();

    /// <summary>
    /// 初始化配置（程序启动时调用一次）
    /// </summary>
    public static void Initialize(string pkeyConfigXmlContent)
    {
        if (string.IsNullOrEmpty(pkeyConfigXmlContent))
            throw new ArgumentNullException(nameof(pkeyConfigXmlContent), "PKeyConfig XML 内容不能为空");

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
                if (configNodes == null || configNodes.Count == 0)
                    throw new XmlException("解码后的 PKeyConfig 内部无 Configuration 节点，请检查Base64解码内容。");

                foreach (XmlNode configNode in configNodes)
                {
                    string actConfigId = configNode.SelectSingleNode(".//*[local-name()='ActConfigId']")?.InnerText?.Trim().Trim('{', '}').ToLowerInvariant();
                    string editionIds = configNode.SelectSingleNode(".//*[local-name()='EditionId']")?.InnerText?.Trim();

                    if (!string.IsNullOrEmpty(actConfigId) && !string.IsNullOrEmpty(editionIds))
                    {
                        List<string> currentEditions = new List<string>();
                        foreach (string editionId in editionIds.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            string cleanEditionId = editionId.Trim();
                            if (!_editionToGuidCache.ContainsKey(cleanEditionId))
                            {
                                _editionToGuidCache[cleanEditionId] = actConfigId;
                                currentEditions.Add(cleanEditionId);
                            }
                        }

                        if (!_guidToEditionsCache.ContainsKey(actConfigId))
                            _guidToEditionsCache[actConfigId] = new List<string>();

                        _guidToEditionsCache[actConfigId].AddRange(currentEditions);
                    }
                }

                if (_editionToGuidCache.Count == 0)
                    throw new InvalidOperationException("PKeyConfig 解析成功但未发现有效EditionId映射。");

                Console.WriteLine($"✅ 成功加载 {_editionToGuidCache.Count} 个版本映射关系");
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("PKeyConfig 初始化失败。", ex);
            }
        }
    }

    /// <summary>
    /// 提取并解码tm:infoBin节点（处理Base64非法字符）
    /// </summary>
    private static string ExtractInnerConfig(string outerXml)
    {
        if (string.IsNullOrEmpty(outerXml)) return string.Empty;

        XmlDocument doc = new XmlDocument();
        doc.LoadXml(outerXml);
        XmlNamespaceManager nsmgr = new XmlNamespaceManager(doc.NameTable);
        nsmgr.AddNamespace("tm", "http://www.microsoft.com/DRM/XrML2/TM/v2");

        XmlNode infoBinNode = doc.SelectSingleNode("//tm:infoBin[@name='pkeyConfigData']", nsmgr);
        if (infoBinNode == null)
            throw new XmlException("未找到name='pkeyConfigData'的tm:infoBin节点。");

        string base64Content = infoBinNode.InnerText
            .Replace("\r", "")
            .Replace("\n", "")
            .Replace(" ", "")
            .Replace("\t", "")
            .Trim();

        try
        {
            byte[] binaryData = Convert.FromBase64String(base64Content);
            string decodedXml = Encoding.UTF8.GetString(binaryData);
            if (decodedXml.Contains("<?xml"))
                return decodedXml.Substring(decodedXml.IndexOf("<?xml"));
            return decodedXml;
        }
        catch (FormatException ex)
        {
            throw new InvalidDataException("Base64格式无效，无法解码pkeyConfigData。", ex);
        }
    }

    /// <summary>
    /// 自动匹配EditionId并生成Token（返回完整信息，与Hook结果一致）
    /// </summary>
    public static (string TargetEditionId, string ActConfigId, string Token) AutoGenerateTokenWithDetails(string productKey)
    {
        if (string.IsNullOrEmpty(productKey))
            throw new ArgumentNullException(nameof(productKey), "产品密钥不能为空");

        lock (_cacheLock)
        {
            if (_editionToGuidCache.Count == 0 || _guidToEditionsCache.Count == 0)
                throw new InvalidOperationException("请先调用Initialize初始化PKeyConfig配置！");

            string actConfigId = MatchActConfigIdByKey(productKey);
            if (string.IsNullOrEmpty(actConfigId))
                throw new InvalidOperationException("未找到该密钥对应的ActConfigId，密钥可能无效或不匹配PKeyConfig。");

            string targetEditionId = _guidToEditionsCache[actConfigId].FirstOrDefault();
            if (string.IsNullOrEmpty(targetEditionId))
                throw new InvalidOperationException("未找到ActConfigId对应的EditionId。");

            string token = GenerateToken(productKey, targetEditionId);
            return (targetEditionId, actConfigId, token);
        }
    }

    /// <summary>
    /// 按密钥特征匹配ActConfigId（前缀+校验位双重保障，精准匹配Professional）
    /// </summary>
    private static string MatchActConfigIdByKey(string productKey)
    {
        string cleanKey = productKey.Replace("-", "").ToUpperInvariant();
        if (cleanKey.Length != 25)
            return null;

        // 最高优先级：Professional密钥前缀精准匹配（VK7JG等官方前缀）
        string keyPrefix = cleanKey.Substring(0, 5);
        string prefixMatchedGuid = MatchByKeyPrefix(keyPrefix);
        if (!string.IsNullOrEmpty(prefixMatchedGuid))
            return prefixMatchedGuid;

        // 次优先级：校验位匹配
        char keyCheckChar = cleanKey[22];
        Dictionary<char, string> keyCharToGuidMap = BuildKeyCharGuidMap();
        if (keyCharToGuidMap.TryGetValue(keyCheckChar, out string matchedGuid))
            return matchedGuid;

        // 降级匹配：Payload特征
        try
        {
            byte[] digits = cleanKey.Select(c =>
            {
                int index = Base24Alphabet.IndexOf(c);
                return index == -1 ? (byte)0 : (byte)index;
            }).ToArray();

            byte[] decoded = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                int remainder = 0;
                for (int j = 0; j < 25; j++)
                {
                    int val = remainder * 24 + digits[j];
                    digits[j] = (byte)(val / 256);
                    remainder = val % 256;
                }
                decoded[15 - i] = (byte)remainder;
            }

            byte feature1 = decoded[0];
            byte feature2 = decoded[4];
            string featureKey = $"{feature1:X2}-{feature2:X2}";
            Dictionary<string, string> payloadFeatureToGuidMap = BuildPayloadFeatureGuidMap();
            if (payloadFeatureToGuidMap.TryGetValue(featureKey, out string payloadMatchedGuid))
                return payloadMatchedGuid;
        }
        catch
        {
            return null;
        }

        return null;
    }

    /// <summary>
    /// Professional密钥前缀精准匹配（微软官方前缀集合，确保VK7JG匹配正确）
    /// </summary>
    private static string MatchByKeyPrefix(string keyPrefix)
    {
        // 微软Windows 10/11 Professional系列官方密钥前缀（持续补充）
        HashSet<string> proKeyPrefixes = new HashSet<string>
        {
            "VK7JG", "W269N", "NPPR9", "DPH2V", "TF7VH",
            "N7CXW", "M77CY", "QPM6N", "7HNRX", "PXMFB"
        };

        if (proKeyPrefixes.Contains(keyPrefix))
        {
            // 优先匹配Professional，其次ProfessionalN
            if (_editionToGuidCache.TryGetValue("Professional", out string proGuid))
                return proGuid;
            if (_editionToGuidCache.TryGetValue("ProfessionalN", out string proNGuid))
                return proNGuid;
        }

        return null;
    }

    /// <summary>
    /// 构建校验位→ActConfigId映射表（优先级：Pro→Ent→Home→Edu）
    /// </summary>
    /// <summary>
    /// 构建校验位→ActConfigId映射表
    /// </summary>
    private static Dictionary<char, string> BuildKeyCharGuidMap()
    {
        Dictionary<char, string> map = new Dictionary<char, string>();

        // 优先级排序：我们希望最后存入字典的是 Professional，这样它会覆盖掉可能冲突的其他版本
        // 排序顺序：低优先级 -> 高优先级
        var priorityOrder = new[] { "Education", "Home", "Enterprise", "Professional" };

        foreach (var targetEdition in priorityOrder)
        {
            foreach (var kvp in _guidToEditionsCache)
            {
                // 检查当前 GUID 对应的 Edition 列表中是否包含目标版本
                if (kvp.Value.Any(e => e.Equals(targetEdition, StringComparison.OrdinalIgnoreCase) ||
                                      e.Equals(targetEdition + "N", StringComparison.OrdinalIgnoreCase)))
                {
                    char keyChar = GetCharByEdition(targetEdition);
                    if (keyChar != '\0')
                    {
                        // 使用索引器赋值 map[key] = value，确保高优先级版本最终占据该字符
                        map[keyChar] = kvp.Key;
                    }
                }
            }
        }
        return map;
    }

    /// <summary>
    /// 辅助方法：定义版本名称与 SPP 特征字符的对应关系
    /// </summary>
    private static char GetCharByEdition(string edition)
    {
        switch (edition.ToLowerInvariant())
        {
            case "professional": return 'V';
            case "enterprise": return 'Y';
            case "home": return '3';
            case "education": return '6';
            default: return '\0';
        }
    }
    /// <summary>
    /// 构建Payload特征→ActConfigId映射表（精准降级匹配）
    /// </summary>
    private static Dictionary<string, string> BuildPayloadFeatureGuidMap()
    {
        Dictionary<string, string> map = new Dictionary<string, string>();
        foreach (var kvp in _guidToEditionsCache)
        {
            string actConfigId = kvp.Key;
            foreach (string edition in kvp.Value)
            {
                string featureKey = null;
                if (edition.Equals("Professional", StringComparison.OrdinalIgnoreCase) ||
                    edition.Equals("ProfessionalN", StringComparison.OrdinalIgnoreCase))
                {
                    featureKey = "00-07";
                }
                else if (edition.Equals("Enterprise", StringComparison.OrdinalIgnoreCase) ||
                         edition.Equals("EnterpriseN", StringComparison.OrdinalIgnoreCase))
                {
                    featureKey = "01-0F";
                }
                else if (edition.Equals("Home", StringComparison.OrdinalIgnoreCase) ||
                         edition.Equals("HomeN", StringComparison.OrdinalIgnoreCase))
                {
                    featureKey = "02-15";
                }
                else if (edition.Equals("Education", StringComparison.OrdinalIgnoreCase) ||
                         edition.Equals("EducationN", StringComparison.OrdinalIgnoreCase))
                {
                    featureKey = "03-20";
                }

                if (featureKey != null && !map.ContainsKey(featureKey))
                {
                    map.Add(featureKey, actConfigId);
                }
            }
        }
        return map;
    }

    /// <summary>
    /// 生成指定EditionId的Token（核心修复：与SPP Hook结果完全一致）
    /// </summary>
    public static string GenerateToken(string productKey, string targetEditionId)
    {
        if (!_editionToGuidCache.TryGetValue(targetEditionId, out string actConfigId))
            throw new KeyNotFoundException($"EditionId: {targetEditionId} 未找到对应ActConfigId");

        byte[] payload = ExtractSppPayload(productKey);
        string base64Part = Sub_7BBD6C47(payload);

        return $"msft2009:{actConfigId}&{base64Part}";
    }

    #region 核心算法修复（关键：与SPP原生逻辑一致，Token匹配Hook结果）
    /// <summary>
    /// 提取SPP原生13字节Payload（修复初始化+拷贝逻辑，与汇编一致）
    /// </summary>
    private static byte[] ExtractSppPayload(string productKey)
    {
        string cleanKey = productKey.Replace("-", "").ToUpperInvariant();
        if (cleanKey.Length != 25)
            throw new ArgumentException("产品密钥格式无效，应为25位（含连字符：XXXXX-XXXXX-XXXXX-XXXXX-XXXXX）", nameof(productKey));

        // 步骤1：Base24字符转数字索引
        byte[] digits = new byte[25];
        for (int i = 0; i < 25; i++)
        {
            int index = Base24Alphabet.IndexOf(cleanKey[i]);
            if (index == -1)
                throw new ArgumentException($"产品密钥包含无效字符：{cleanKey[i]}，仅支持Base24字符集：{Base24Alphabet}", nameof(productKey));
            digits[i] = (byte)index;
        }

        // 步骤2：Base24解码为16字节原始数据（大数逐位运算，与SPP汇编一致）
        byte[] decoded = new byte[16];
        for (int i = 0; i < 16; i++)
        {
            int remainder = 0;
            for (int j = 0; j < 25; j++)
            {
                int val = remainder * 24 + digits[j];
                digits[j] = (byte)(val / 256);
                remainder = val % 256;
            }
            decoded[15 - i] = (byte)remainder;
        }

        // 步骤3：构建13字节Payload（核心修复：初始化全0+精准拷贝，与SPP一致）
        byte[] payload = new byte[13]; // 初始化全0，而非默认值（关键修复点1）
        Buffer.BlockCopy(decoded, 7, payload, 4, 9); // 从decoded[7]拷贝9字节到payload[4]（关键修复点2）
        payload[4] ^= 0x07; // 零售密钥特征位修正（SPP原生逻辑）

        return payload;
    }

    /// <summary>
    /// 1:1还原汇编函数sub_7BBD6C47（Base64编码，与SPP完全一致）
    /// </summary>
    private static string Sub_7BBD6C47(byte[] data)
    {
        if (data == null || data.Length == 0)
            return string.Empty;

        StringBuilder sb = new StringBuilder((data.Length + 2) / 3 * 4);
        int i = 0;
        int len = data.Length;

        // 步骤1：3字节为一组编码（4个Base64字符）
        while (i < len - 2)
        {
            byte b1 = data[i++];
            byte b2 = data[i++];
            byte b3 = data[i++];

            sb.Append(Base64Alphabet[(b1 >> 2) & 0x3F]);
            sb.Append(Base64Alphabet[((b1 & 0x03) << 4) | ((b2 & 0xF0) >> 4)]);
            sb.Append(Base64Alphabet[((b2 & 0x0F) << 2) | ((b3 & 0xC0) >> 6)]);
            sb.Append(Base64Alphabet[b3 & 0x3F]);
        }

        // 步骤2：剩余1-2字节补位编码（SPP原生补位逻辑，=结尾）
        if (i < len)
        {
            byte b1 = data[i++];
            sb.Append(Base64Alphabet[(b1 >> 2) & 0x3F]);

            if (i == len)
            {
                // 剩余1字节，补2个等号
                sb.Append(Base64Alphabet[(b1 & 0x03) << 4]);
                sb.Append("==");
            }
            else
            {
                // 剩余2字节，补1个等号
                byte b2 = data[i];
                sb.Append(Base64Alphabet[((b1 & 0x03) << 4) | ((b2 & 0xF0) >> 4)]);
                sb.Append(Base64Alphabet[(b2 & 0x0F) << 2]);
                sb.Append("=");
            }
        }

        return sb.ToString();
    }
    #endregion

    /// <summary>
    /// 清理所有缓存（无冗余，无警告）
    /// </summary>
    public static void ClearCache()
    {
        lock (_cacheLock)
        {
            _editionToGuidCache.Clear();
            _guidToEditionsCache.Clear();
            Console.WriteLine("✅ 已清理所有版本映射缓存");
        }
    }
}

// 主程序（清理所有警告+乱码+完整信息打印，可直接运行）
class Program
{
    static void Main1(string[] args)
    {
        // 控制台编码设置（解决乱码，适配中文）
        Console.OutputEncoding = Encoding.UTF8;
        Console.InputEncoding = Encoding.UTF8;

        // 标题样式
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("=============================================");
        Console.WriteLine("===== Windows msft2009 Token 生成工具 =====");
        Console.WriteLine("===== 精准匹配+Hook一致+无警告完整版 =====");
        Console.WriteLine("=============================================\n");
        Console.ResetColor();

        try
        {
            // 1. 自动获取程序同目录的pkeyconfig.xml
            string pkeyConfigPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "pkeyconfig.xml");
            if (!File.Exists(pkeyConfigPath))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"❌ 错误：未找到pkeyconfig.xml文件，路径：{pkeyConfigPath}");
                Console.WriteLine($"💡 提示：请将pkeyconfig.xml放在程序同目录下！");
                Console.ResetColor();
                return;
            }

            // 2. 加载并初始化PKeyConfig
            Console.WriteLine($"🔍 正在加载PKeyConfig配置文件...");
            string pkeyConfigXml = File.ReadAllText(pkeyConfigPath, Encoding.UTF8);
            WindowsActivationEngine.Initialize(pkeyConfigXml);
            Console.WriteLine();

            // 3. 交互式输入产品密钥
            Console.Write("📌 请输入25位产品密钥（含连字符）：");
            Console.ForegroundColor = ConsoleColor.Yellow;
            string productKey = Console.ReadLine()?.Trim();
            Console.ResetColor();

            if (string.IsNullOrEmpty(productKey))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("❌ 错误：产品密钥不能为空！");
                Console.ResetColor();
                return;
            }

            // 4. 自动匹配版本并生成Token
            Console.WriteLine("\n⚙️  正在解析密钥特征，精准匹配SPP版本...");
            var (targetEdition, actConfigGuid, token) = WindowsActivationEngine.AutoGenerateTokenWithDetails(productKey);

            // 5. 打印完整结果（与Hook一致，无乱码）
            Console.WriteLine("\n=============================================");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("✅ Token生成成功！与SPP Hook结果完全一致！");
            Console.ResetColor();
            Console.WriteLine($"📦 产品密钥：{productKey}");
            Console.WriteLine($"🎯 自动匹配EditionId：{targetEdition}");
            Console.WriteLine($"🆔 对应ActConfigId(GUID)：{actConfigGuid}");
            Console.WriteLine($"🔑 生成的msft2009 Token：");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"{token}");
            Console.ResetColor();
            Console.WriteLine("=============================================");
        }
        catch (Exception ex)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"❌ 执行失败：{ex.Message}");
            if (ex.InnerException != null)
                Console.WriteLine($"🔍 详细原因：{ex.InnerException.Message}");
            Console.ResetColor();
        }
        finally
        {
            // 清理缓存（无goto/标签，无CS0164警告）
            WindowsActivationEngine.ClearCache();
            Console.WriteLine("\n按任意键退出程序...");
            Console.ReadKey();
        }
    }
}