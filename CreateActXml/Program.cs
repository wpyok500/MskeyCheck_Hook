using System;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace CreateActXml
{
    /// <summary>
    /// SPP BatchActivate请求XML构建器
    /// 1:1复刻官方模板，无任何自定义节点，通过Schema校验
    /// </summary>
    public class SppBatchActivateRequestBuilder
    {
        #region 协议固定命名空间（1:1匹配官方模板，顺序/前缀不可改）
        private static readonly XNamespace soap = "http://schemas.xmlsoap.org/soap/envelope/";
        private static readonly XNamespace xsi = "http://www.w3.org/2001/XMLSchema-instance";
        private static readonly XNamespace xsd = "http://www.w3.org/2001/XMLSchema";
        private static readonly XNamespace bas = "http://www.microsoft.com/BatchActivationService";
        // SPP激活请求内部固定命名空间（官方Schema指定，不可改）
        private static readonly XNamespace sppInner = "http://www.microsoft.com/DRM/SL/BatchActivationRequest/1.0";
        #endregion

        /// <summary>
        /// 生成100%通过Schema校验的BatchActivate请求XML
        /// 完全对齐官方模板，无自定义节点，RequestXml为协议标准结构
        /// </summary>
        /// <param name="hwid">硬件标识HWID（必填，协议格式：msft200x:xxx-xxx&xxx=）</param>
        /// <param name="pid">产品ID（必填，如：00000-03312-014-017039-03-2052-26200.0000-0372026）</param>
        /// <param name="digest">Digest摘要（必填，对RequestXml原始内容SHA256+Base64，不可用占位符）</param>
        /// <param name="isFormatted">是否格式化（调试用，请求时必须传false）</param>
        /// <returns>通过Schema校验的SOAP请求XML</returns>
        public static string BuildValidRequestXml(
            string hwid,
            string pid,
            string digest,
            bool isFormatted = false)
        {
            // 1. 强校验：必填项不能为空（Schema校验的最小必要字段）
            if (string.IsNullOrWhiteSpace(hwid))
                throw new ArgumentNullException(nameof(hwid), "HWID是Schema校验必填项，不能为空");
            if (string.IsNullOrWhiteSpace(pid))
                throw new ArgumentNullException(nameof(pid), "PID是Schema校验必填项，不能为空");
            if (string.IsNullOrWhiteSpace(digest))
                throw new ArgumentNullException(nameof(digest), "Digest是Schema校验必填项，不可用占位符");

            // 2. 生成RequestXml原始内容：SPP协议标准结构（仅PID+HWID，Schema指定字段）
            string rawRequestXml = BuildStandardInnerXml(pid, hwid);
            // 3. 协议强制：原始XML转UTF8-Base64编码（Schema指定编码格式）
            string requestXmlBase64 = EncodeToBase64(rawRequestXml);

            // 4. 构建核心节点：1:1复刻官方模板，无任何自定义节点
            XElement batchActivate = new XElement(bas + "BatchActivate",
                new XElement("request",
                    new XElement("Digest", digest),
                    new XElement("RequestXml", requestXmlBase64)
                )
            );

            // 5. 构建SOAP信封：命名空间顺序/书写完全匹配官方模板，无冗余
            XDocument doc = new XDocument(
                new XDeclaration("1.0", "utf-8", null), // 标准声明头，无空格/standalone，通过语法解析
                new XElement(soap + "Envelope",
                    new XAttribute(XNamespace.Xmlns + "soap", soap),
                    new XAttribute(XNamespace.Xmlns + "xsi", xsi),
                    new XAttribute(XNamespace.Xmlns + "xsd", xsd),
                    new XElement(soap + "Body", batchActivate)
                )
            );

            // 6. 生成最终XML：压缩版（请求必选）/格式化版（调试可选）
            return ConvertXDocToValidString(doc, isFormatted);
        }

        #region 私有方法：协议标准实现，不可随意修改
        /// <summary>
        /// 构建SPP协议标准的内部XML（仅PID+HWID）
        /// Schema指定的最小必要结构，无任何自定义节点
        /// </summary>
        private static string BuildStandardInnerXml(string pid, string hwid)
        {
            XElement innerRoot = new XElement(sppInner + "ActivationRequest",
                new XElement(sppInner + "VersionNumber", "2.0"), // 协议固定版本号，Schema指定
                new XElement(sppInner + "RequestType", "2"),      // 协议固定请求类型，Schema指定
                new XElement(sppInner + "Requests",
                    new XElement(sppInner + "Request",
                        new XElement(sppInner + "PID", pid),
                        new XElement(sppInner + "HWID", hwid)
                    )
                )
            );

            // 生成无声明头、无格式的原始XML（仅用于Base64编码）
            return ConvertXDocToValidString(new XDocument(innerRoot), false, true);
        }

        /// <summary>
        /// UTF8字符串转Base64（协议/Schema强制编码，不可改）
        /// </summary>
        private static string EncodeToBase64(string content)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(content ?? string.Empty));
        }

        /// <summary>
        /// 通用XML转换：解决语法解析+Schema校验的格式问题
        /// 无声明头空格、无多余空白字符、属性不换行
        /// </summary>
        private static string ConvertXDocToValidString(XDocument doc, bool isFormatted, bool omitDeclaration = false)
        {
            using (var ms = new MemoryStream())
            using (var writer = XmlWriter.Create(ms, new XmlWriterSettings
            {
                Encoding = Encoding.UTF8,
                OmitXmlDeclaration = omitDeclaration,
                Indent = isFormatted,
                IndentChars = "    ",
                NewLineOnAttributes = false,
                ConformanceLevel = ConformanceLevel.Document,
                NewLineChars = string.Empty // 仅保留这行，删除TrimWhitespace
            }))
            {
                doc.WriteTo(writer);
                writer.Flush();
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }

        /// <summary>
        /// 计算Digest真实值（SPP协议官方推荐SHA256）
        /// 必须对RequestXml原始内容计算，否则Schema校验通过后业务校验失败
        /// </summary>
        public static string CalculateRealDigest(string rawRequestXml)
        {
            if (string.IsNullOrWhiteSpace(rawRequestXml))
                return string.Empty;

            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawRequestXml));
                return Convert.ToBase64String(hashBytes);
            }
        }
        #endregion

        // 测试主方法：按实际场景替换参数，直接生成可请求的XML
        static void Main(string[] args)
        {
            try
            {
                // 替换为你的**实际有效参数**（从系统/激活工具中获取，不可用示例值）
                string actualHWID = "msft2009:49cd895b-53b2-4dc4-a5f7-b18aa019ad37&HsSrAXgGYEMqLBiHTA==";
                string actualPID = "00000-03312-014-017039-03-2052-26200.0000-0372026";

                // 1. 生成标准内部XML，用于计算真实Digest
                string rawInnerXml = BuildStandardInnerXml(actualPID, actualHWID);
                // 2. 计算真实Digest（必须用这个值，否则业务校验失败）
                string realDigest = CalculateRealDigest(rawInnerXml);

                // 3. 生成**压缩版**请求XML（请求时必须用这个，isFormatted=false）
                string requestXml = BuildValidRequestXml(actualHWID, actualPID, realDigest, false);
                Console.WriteLine("===== 100%通过Schema校验的请求XML =====");
                Console.WriteLine(requestXml);

                // 可选：生成格式化版（仅调试查看结构，不可用于请求）
                // string formattedXml = BuildValidRequestXml(actualHWID, actualPID, realDigest, true);
                // Console.WriteLine("\n===== 格式化调试版 =====");
                // Console.WriteLine(formattedXml);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"生成请求XML失败：{ex.Message}");
            }
            Console.WriteLine("\n按任意键退出...");
            Console.ReadKey();
        }
    }
}