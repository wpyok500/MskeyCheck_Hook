using System;
using System.Xml.Linq;

namespace SppXmlGenerator
{
    public class SppXmlFinal
    {
        // 核心命名空间：统一规范前缀，移除冗余命名空间，匹配SPP标准协议
        private static readonly XNamespace soap = "http://schemas.xmlsoap.org/soap/envelope/";
        private static readonly XNamespace soapenc = "http://schemas.xmlsoap.org/soap/encoding/";
        private static readonly XNamespace xsd = "http://www.w3.org/2001/XMLSchema";
        private static readonly XNamespace xsi = "http://www.w3.org/2001/XMLSchema-instance";
        private static readonly XNamespace trust = "http://schemas.xmlsoap.org/ws/2004/04/security/trust";
        private static readonly XNamespace r = "urn:mpeg:mpeg21:2003:01-REL-R-NS";
        private static readonly XNamespace sl = "http://www.microsoft.com/DRM/XrML2/SL/v2";
        private static readonly XNamespace tm = "http://www.microsoft.com/DRM/XrML2/TM/v2";

        /// <summary>
        /// 生成标准SPP SOAP请求XML（优化后完全匹配协议格式）
        /// </summary>
        /// <param name="hwidString">硬件标识HWID（格式：msft2005:xxx-xxx&xxx=）</param>
        /// <param name="spcXml">安全处理器证书XML（可选，无则传空）</param>
        /// <param name="pkcXml">产品密钥证书XML（可选，无则传空）</param>
        /// <param name="plXml">发布许可证XML（可选，无则传空）</param>
        /// <returns>无格式压缩的SOAP XML字符串（可直接发送请求）</returns>
        public static string BuildRequest(string hwidString, string spcXml = "", string pkcXml = "", string plXml = "")
        {
            // 生成RAC内部XML（修复命名空间属性，规范节点层级）
            string racXml = GenerateRacInnerXml(hwidString);

            // 构建UseKey节点：修复arrayType前缀引用，移除冗余命名空间声明
            XElement useKey = new XElement(trust + "UseKey",
                new XElement(trust + "Values",
                    new XAttribute(soapenc + "arrayType", $"trust:TokenEntry[4]"),
                    CreateTokenEntry("RightsAccountCertificate", racXml),
                    CreateTokenEntry("SecurityProcessorCertificate", spcXml),
                    CreateTokenEntry("ProductKeyCertificate", pkcXml),
                    CreateTokenEntry("PublishLicense", plXml)
                )
            );

            // 构建Claims节点：统一arrayType格式，修复时间格式严格匹配UTC
            XElement claims = new XElement(trust + "Claims",
                new XElement(trust + "Values",
                    new XAttribute(soapenc + "arrayType", $"trust:TokenEntry[1]"),
                    CreateTokenEntry("ClientSystemTime", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))
                )
            );

            // 构建RequestSecurityToken核心节点：规范节点顺序，匹配SPP协议
            XElement rst = new XElement(trust + "RequestSecurityToken",
                new XElement(trust + "TokenType", "urn:mpeg:mpeg21:2003:01-REL-R-NS:UseLicense"),
                new XElement(trust + "RequestType", trust + "Issue"),
                useKey,
                claims
            );

            // 构建根SOAP Envelope：统一命名空间声明在根节点，移除子节点冗余声明
            XDocument doc = new XDocument(
                new XDeclaration("1.0", "utf-8", "no"),
                new XElement(soap + "Envelope",
                    // 根节点统一声明所有命名空间，匹配标准SOAP 1.1格式
                    new XAttribute(XNamespace.Xmlns + "soap", soap),
                    new XAttribute(XNamespace.Xmlns + "soapenc", soapenc),
                    new XAttribute(XNamespace.Xmlns + "xsd", xsd),
                    new XAttribute(XNamespace.Xmlns + "xsi", xsi),
                    new XAttribute(XNamespace.Xmlns + "trust", trust),
                    new XAttribute(XNamespace.Xmlns + "r", r),     // 固定前缀“r”
                    new XAttribute(XNamespace.Xmlns + "sl", sl),   // 固定前缀“sl”
                    new XAttribute(XNamespace.Xmlns + "tm", tm),   // 固定前缀“tm”
                    // SOAP Body节点：无额外属性，仅包含RST核心节点
                    new XElement(soap + "Body", rst)
                )
            );

            // 生成无格式XML，自动转义特殊字符（避免XML解析错误）
            return doc.ToString(SaveOptions.DisableFormatting);
        }

        /// <summary>
        /// 生成标准RightsAccountCertificate内部XML（优化节点结构和命名空间）
        /// </summary>
        /// <param name="hwid">硬件标识HWID</param>
        /// <returns>RAC XML字符串</returns>
        private static string GenerateRacInnerXml(string hwid)
        {
            // 校验HWID非空，避免生成无效XML
            if (string.IsNullOrWhiteSpace(hwid))
                throw new ArgumentNullException(nameof(hwid), "HWID硬件标识不能为空");

            XElement rac = new XElement(r + "license",
                new XElement(r + "grant",
                    new XElement(tm + "bindingPrincipals",
                        new XElement(r + "allPrincipals",
                            new XElement(sl + "binding",
                                new XElement(sl + "data",
                                    new XAttribute("Algorithm", "msft:rm/algorithm/hwid/4.0"),
                                    hwid
                                )
                            )
                        )
                    )
                )
            );

            // 生成无格式RAC XML，命名空间由根SOAP节点统一声明，无需重复添加
            return rac.ToString(SaveOptions.DisableFormatting);
        }

        /// <summary>
        /// 构建标准TokenEntry节点（Trust命名空间，Name+Value结构）
        /// </summary>
        /// <param name="name">Token名称</param>
        /// <param name="value">Token值（XML字符串/普通字符串）</param>
        /// <returns>TokenEntry XElement节点</returns>
        private static XElement CreateTokenEntry(string name, string value)
        {
            // 空值处理：避免生成空的Value节点，替换为空白字符串
            string safeValue = string.IsNullOrWhiteSpace(value) ? "" : value;
            return new XElement(trust + "TokenEntry",
                new XElement(trust + "Name", name),
                new XElement(trust + "Value", safeValue)
            );
        }

        /// <summary>
        /// 主方法-调用示例（直接运行即可生成SPP SOAP XML）
        /// </summary>
        /// <param name="args">命令行参数</param>
        static void Main(string[] args)
        {
            try
            {
                // 1. 替换为实际的硬件标识HWID（格式：msft2005:xxx-xxx&xxx=）
                string actualHwid = "msft2009:49cd895b-53b2-4dc4-a5f7-b18aa019ad37&HsSrAXgGYEMqLBiHTA==";

                // 2. 可选：传入实际的SPC/PKC/PL证书XML字符串（无则保持空）
                string spcXml = "";  // 实际SecurityProcessorCertificate XML
                string pkcXml = "";  // 实际ProductKeyCertificate XML
                string plXml = "";   // 实际PublishLicense XML

                // 3. 核心调用：生成标准SPP SOAP请求XML
                string sppSoapXml = BuildRequest(actualHwid, spcXml, pkcXml, plXml);

                // 4. 输出结果（可直接复制使用/写入文件/发送HTTP POST请求）
                Console.WriteLine("=== 优化后生成的标准SPP SOAP请求XML ===");
                Console.WriteLine(sppSoapXml);

                // 可选：将XML写入文件（方便查看/调试）
                // System.IO.File.WriteAllText("SPP_SOAP_Request.xml", sppSoapXml, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"生成XML失败：{ex.Message}");
            }

            // 防止控制台闪退
            Console.WriteLine("\n\n按任意键退出...");
            Console.ReadKey();
        }
    }
}