using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml.Linq;
using System.Xml.Serialization;

public static class PKeyConfigLoader
{
    /// <summary>
    /// 从 pkey 文件 解码 → 读取全部配置（Configuration/KeyRange/PublicKey）
    /// </summary>
    public static ProductKeyConfiguration LoadFullConfig(string pkeyFilePath)
    {
        try
        {
            // ====================== 1. 加载外部XML ======================
            XDocument xDoc = XDocument.Load(pkeyFilePath);

            // ====================== 2. 命名空间 ======================
            XNamespace tmNs = "http://www.microsoft.com/DRM/XrML2/TM/v2";
            XNamespace pkcNs = "http://www.microsoft.com/DRM/PKEY/Configuration/2.0";

            // ====================== 3. 提取 Base64 节点 ======================
            var binElement = xDoc.Descendants(tmNs + "infoBin")
                .FirstOrDefault(e =>
                {
                    var attr = e.Attribute("name");
                    return attr != null && attr.Value == "pkeyConfigData";
                });

            if (binElement == null || string.IsNullOrWhiteSpace(binElement.Value))
                throw new Exception("未找到 pkeyConfigData 节点");

            // ====================== 4. 解码 Base64 → 得到内部XML ======================
            byte[] bytes = Convert.FromBase64String(binElement.Value);
            string innerXml = Encoding.UTF8.GetString(bytes);

            // ====================== 5. 反序列化 → 自动加载所有多组节点 ======================
            XmlSerializer serializer = new XmlSerializer(typeof(ProductKeyConfiguration));
            using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(innerXml)))
            {
                return (ProductKeyConfiguration)serializer.Deserialize(ms);
            }
        }
        catch (Exception ex)
        {
            throw new Exception("解码并解析PKey配置失败: " + ex.Message, ex);
        }
    }

    // ====================== 你要的查询方法 ======================
    /// <summary>
    /// 根据 AID + EditionId 查询 Configuration 对象
    /// </summary>
    public static Configuration GetProductDescription(ProductKeyConfiguration config, string aid, string editionId)
    {
        if (config == null || config.Configurations == null)
            return null;

        // 标准化 AID，自动包裹 { }
        string cleanAid = aid.Trim().Replace("{", "").Replace("}", "");
        string targetAid = $"{{{cleanAid}}}";

        // 标准化查询条件
        string searchEdi = string.IsNullOrWhiteSpace(editionId) ? "" : editionId.Trim();

        // 返回匹配的 Configuration 对象
        return Array.Find(config.Configurations, c =>
            string.Equals(c.ActConfigId, targetAid, StringComparison.OrdinalIgnoreCase) &&
            (string.IsNullOrEmpty(searchEdi) || c.EditionId.IndexOf(searchEdi, StringComparison.OrdinalIgnoreCase) >= 0)
        );
    }

    public static List<Configuration> GetByGroupId(ProductKeyConfiguration config, uint groupId)
    {
        if (config == null || config.Configurations == null)
            return new List<Configuration>();

        return Array.FindAll(config.Configurations, c => c.RefGroupId == groupId).ToList();
    }
}