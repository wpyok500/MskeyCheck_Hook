using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.UI.WebControls;
using System.Xml;

// .NET 4.8 需添加程序集引用：
// System.Net.Http、System.Web、System.Xml、System.Core、System.Configuration
namespace CreateActXml
{
    /// <summary>
    /// 微软产品密钥激活结果查询API（获取HResult错误码）
    /// 支持2005/2009版本，Win/Office产品激活校验
    /// .NET Framework 4.8 重构版
    /// </summary>
    public class ProductActivationApi
    {
        #region 常量定义（硬编码抽离，便于统一维护）
        /// <summary>
        /// 默认用户代理
        /// </summary>
        private const string DefaultUserAgent = "SLSSoapClient";
        /// <summary>
        /// 默认编码（UTF8无BOM）
        /// </summary>
        private static readonly Encoding Utf8NoBom = new UTF8Encoding(false);
        /// <summary>
        /// XML内容类型
        /// </summary>
        private const string ContentTypeXml = "text/xml";
        /// <summary>
        /// SOAP命名空间相关常量
        /// </summary>
        private static class SoapNs
        {
            public const string Envelope = "http://schemas.xmlsoap.org/soap/envelope/";
            public const string Encoding = "http://schemas.xmlsoap.org/soap/encoding/";
            public const string Trust = "http://schemas.xmlsoap.org/ws/2004/04/security/trust";
            public const string Xsd = "http://www.w3.org/2001/XMLSchema";
            public const string Xsi = "http://www.w3.org/2001/XMLSchema-instance";
            public const string IssueRequestType = "http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue";
        }
        /// <summary>
        /// 激活令牌类型常量
        /// </summary>
        private static class TokenType
        {
            public const string SPC = "SPC";
            public const string RAC = "RAC";
            public const string PKC = "PKC";
            public const string UseLicense = "UseLicense";
            public const string ProductActivation = "ProductActivation";
        }
        /// <summary>
        /// 错误码常量
        /// </summary>
        private static class ErrorCode
        {
            public const string Unknown = "Unknown";
            public const string OnlineKey = "Online Key";
            public const string Win2005EulError = "0xC004C008";
            public const string ConnectionAbnormal = "The connection to the Microsoft server is abnormal";
        }
        #endregion

        #region 配置抽离（独立内部类，解耦业务与配置）
        /// <summary>
        /// 激活服务地址配置（URL + SOAPAction）
        /// </summary>
        private class ActivationServiceConfig
        {
            public string Url { get; set; }
            public string SoapAction { get; set; }
        }

        /// <summary>
        /// 版本化激活配置（2005/2009）
        /// </summary>
        private class VersionedActivationConfig
        {
            /// <summary>
            /// 2005版本配置（Win/Office）
            /// </summary>
            public static readonly Dictionary<string, ActivationServiceConfig> Win2005 = new Dictionary<string, ActivationServiceConfig>
            {
                { "SPC", new ActivationServiceConfig { Url = "https://activation.sls.microsoft.com/slspc/SLActivate.asmx?configextension=o14", SoapAction = "http://microsoft.com/SL/ActivationService/IssueToken" } },
                { "RAC", new ActivationServiceConfig { Url = "https://activation.sls.microsoft.com/slrac/SLCertify.asmx", SoapAction = "http://microsoft.com/SL/CertificationService/IssueToken" } },
                { "PKC", new ActivationServiceConfig { Url = "https://activation.sls.microsoft.com/slpkc/SLCertifyProduct.asmx", SoapAction = "http://microsoft.com/SL/ProductCertificationService/IssueToken" } },
                { "EUL", new ActivationServiceConfig { Url = "https://activation.sls.microsoft.com/sllicensing/SLLicense.asmx", SoapAction = "http://microsoft.com/SL/LicensingService/IssueToken" } }
            };

            /// <summary>
            /// 2005版本Office配置
            /// </summary>
            public static readonly Dictionary<string, ActivationServiceConfig> Office2005 = new Dictionary<string, ActivationServiceConfig>
            {
                { "SPC", new ActivationServiceConfig { Url = "https://activation.sls.microsoft.com/slspc/SLActivate.asmx?configextension=o14", SoapAction = "http://microsoft.com/SL/ActivationService/IssueToken" } },
                { "RAC", new ActivationServiceConfig { Url = "https://activation.sls.microsoft.com/slrac/SLCertify.asmx?configextension=o14", SoapAction = "http://microsoft.com/SL/CertificationService/IssueToken" } },
                { "PKC", new ActivationServiceConfig { Url = "https://activation.sls.microsoft.com/slpkc/SLCertifyProduct.asmx?configextension=o14", SoapAction = "http://microsoft.com/SL/ProductCertificationService/IssueToken" } },
                { "EUL", new ActivationServiceConfig { Url = "https://activation.sls.microsoft.com/sllicensing/SLLicense.asmx?configextension=o14", SoapAction = "http://microsoft.com/SL/LicensingService/IssueToken" } }
            };

            /// <summary>
            /// 2009版本Office配置
            /// </summary>
            public static readonly ActivationServiceConfig Office2009PA = new ActivationServiceConfig
            {
                Url = "https://activation.sls.microsoft.com/SLActivateProduct/SLActivateProduct.asmx?configextension=o14",
                SoapAction = "http://microsoft.com/SL/ProductActivationService/IssueToken"
            };
        }

        /// <summary>
        /// 预置声明/密钥字典（原硬编码的Claims/UseKey）
        /// 注：原硬编码的大段XML证书内容保留，仅做命名规范优化
        /// </summary>
        private static class PresetDictionaries
        {
            // HWID相关
            public static readonly byte[] HWID = { 42, 0, 0, 0, 1, 0, 2, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0 };
            public static readonly byte[] HWID1 = { 42, 0, 0, 0, 1, 0, 2, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 150, 43, 54, 158, 200, 66, 82, 200, 158, 214, 126, 148, 36, 29, 251, 53, 252, 37 };
            public static readonly byte[] RandomBuffer = new byte[18];

            // 2005 SPC
            public static readonly Dictionary<string, string> Claims2005SPC = new Dictionary<string, string>
            {
                { "SPVersion", "1.0" },
                { "SPAssuranceLevel", "urn:msft:sl/Assurance/SLS-Default/1.0" },
                { "otherInfoPublic.licenseCategory", "msft:sl/SPC/ACTIVATED/PUBLIC" },
                { "otherInfoPrivate.licenseCategory", "msft:sl/SPC/ACTIVATED/PRIVATE" },
                { "otherInfoPublic.sysprepAction", "rearm" },
                { "otherInfoPrivate.sysprepAction", "rearm" },
                { "otherInfoPublic.spcActivationGroup", "msft:Windows/6.0/SPC/Retail" },
                { "otherInfoPrivate.spcActivationGroup", "msft:Windows/6.0/SPC/Retail" }
            };
            public static readonly Dictionary<string, string> UseKey2005SPC = new Dictionary<string, string>();

            // 2005 PKC
            public static readonly Dictionary<string, string> Claims2005PKC = new Dictionary<string, string>
            {
                { "ProductKey", "RFF6G-C3YCJ-F9CHT-KD6MJ-24P46" },
                { "ProductKeyType", "msft:rm/algorithm/pkey/2005" },
                { "ProductKeyActConfigId", "msft2005:c619d61c-c2f2-40c3-ab3f-c5924314b0f3&IOLFrdsAAAAAAAAA" }
            };
            public static readonly Dictionary<string, string> UseKey2005PKC = new Dictionary<string, string>();

            // 2005 Win RAC
            public static readonly Dictionary<string, string> Claims2005WinRAC = new Dictionary<string, string>
            {
                { "BindingType", "msft:rm/algorithm/hwid/4.0" },
                { "Binding", "KgAAAAEAAgABAAEAAAAAAAAAAQABAAEAeqg2nshCUsie1n6UJB37Nfwl" },
                { "otherInfoPublic.licenseCategory", "msft:sl/RAC/ACTIVATED/PUBLIC" },
                { "otherInfoPrivate.licenseCategory", "msft:sl/RAC/ACTIVATED/PRIVATE" },
                { "otherInfoPublic.sysprepAction", "rearm" },
                { "otherInfoPrivate.sysprepAction", "rearm" },
                { "otherInfoPublic.racActivationGroup", "msft:Windows/6.0/RAC/Retail" },
                { "otherInfoPrivate.racActivationGroup", "msft:Windows/6.0/RAC/Retail" }
            };
            public static readonly Dictionary<string, string> UseKey2005WinRAC = new Dictionary<string, string>
            {
                { "SPCPublicCertificate", GetLargeXml("Win2005RACSPCCert") }
            };

            // 2005 Office RAC
            public static readonly Dictionary<string, string> Claims2005OfficeRAC = new Dictionary<string, string>
            {
                { "BindingType", "msft:rm/algorithm/hwid/4.0" },
                { "Binding", "KgAAAAEAAgABAAEAAAAAAAAAAQABAAEAlis2nshCUsie1n6UJB37Nfwl" },
                { "otherInfoPublic.licenseCategory", "msft:sl/RAC/ACTIVATED/PUBLIC" },
                { "otherInfoPrivate.licenseCategory", "msft:sl/RAC/ACTIVATED/PRIVATE" },
                { "otherInfoPublic.sysprepAction", "rearm" },
                { "otherInfoPrivate.sysprepAction", "rearm" },
                { "otherInfoPublic.racActivationGroup", "msft:Windows/6.0/RAC/Retail" },
                { "otherInfoPrivate.racActivationGroup", "msft:Windows/6.0/RAC/Retail" }
            };
            public static readonly Dictionary<string, string> UseKey2005OfficeRAC = new Dictionary<string, string>
            {
                { "SPCPublicCertificate", GetLargeXml("Office2005RACSPCCert") }
            };

            // 2005 Win EUL
            public static readonly Dictionary<string, string> Claims2005WinEUL = new Dictionary<string, string>
            {
                { "otherInfoPublic.licenseCategory", "msft:sl/EUL/ACTIVATED/PUBLIC" },
                { "otherInfoPrivate.licenseCategory", "msft:sl/EUL/ACTIVATED/PRIVATE" },
                { "otherInfoPublic.sysprepAction", "rearm" },
                { "otherInfoPrivate.sysprepAction", "rearm" },
                { "ClientInformation", "SystemUILanguageId=1033;UserUILanguageId=1033;GeoId=244" },
                { "ReferralInformation", "APPID55c92734-d682-4d71-983e-d6ec3f16059f:ReferralId=000000;" },
                { "ClientSystemTime", "2021-06-14T07:11:02Z" },
                { "otherInfoPublic.secureStoreId", "da14d8a7-0d40-4881-b84f-c478593586ff" },
                { "otherInfoPrivate.secureStoreId", "da14d8a7-0d40-4881-b84f-c478593586ff" }
            };
            public static readonly Dictionary<string, string> UseKey2005WinEUL = new Dictionary<string, string>
            {
                { "SecurityProcessorCertificate", GetLargeXml("Win2005EULSPCCert") },
                { "RightsAccountCertificate", GetLargeXml("Win2005EULRACCert") },
                { "ProductKeyCertificate", GetLargeXml("Win2005EULPKCCert") },
                { "PublishLicense", GetLargeXml("Win2005EULPublishLicense") }
            };

            // 2005 Office EUL
            public static readonly Dictionary<string, string> Claims2005OfficeEUL = new Dictionary<string, string>
            {
                { "otherInfoPublic.licenseCategory", "msft:sl/EUL/ACTIVATED/PUBLIC" },
                { "otherInfoPrivate.licenseCategory", "msft:sl/EUL/ACTIVATED/PRIVATE" },
                { "otherInfoPublic.sysprepAction", "rearm" },
                { "otherInfoPrivate.sysprepAction", "rearm" },
                { "ClientInformation", "SystemUILanguageId=1033;UserUILanguageId=1033;GeoId=244" },
                { "ClientSystemTime", "2021-06-15T03:20:04Z" },
                { "ClientSystemTimeUtc", "2021-06-15T03:20:04Z" },
                { "otherInfoPublic.secureStoreId", "c0195a4b-5feb-42d2-a2c7-953c9d22d70a" },
                { "otherInfoPrivate.secureStoreId", "c0195a4b-5feb-42d2-a2c7-953c9d22d70a" }
            };
            public static readonly Dictionary<string, string> UseKey2005OfficeEUL = new Dictionary<string, string>
            {
                { "SecurityProcessorCertificate", GetLargeXml("Office2005EULSPCCert") },
                { "RightsAccountCertificate", GetLargeXml("Office2005EULRACCert") },
                { "ProductKeyCertificate", GetLargeXml("Office2005EULPKCCert") },
                { "PublishLicense", GetLargeXml("Office2005EULPublishLicense") }
            };

            // 2009 Office
            public static readonly Dictionary<string, string> Claims2009Office = new Dictionary<string, string>
            {
                { "BindingType", "msft:rm/algorithm/hwid/4.0" },
                { "Binding", "KgAAAAEAAgABAAEAAAAAAAAAAQABAAEAlis2nshCUsie1n6UJB37Nfwl" },
                { "ProductKey", "4KHB6-NFWJF-M37Y7-CJTGV-B7V7H" },
                { "ProductKeyType", "msft:rm/algorithm/pkey/2009" },
                { "ProductKeyActConfigId", "msft2009:de52bd50-9564-4adc-8fcb-a345c17f84f9&SKSW8p4GuL98qNuOWA==" },
                { "otherInfoPublic.licenseCategory", "msft:sl/EUL/ACTIVATED/PUBLIC" },
                { "otherInfoPrivate.licenseCategory", "msft:sl/EUL/ACTIVATED/PRIVATE" },
                { "otherInfoPublic.sysprepAction", "rearm" },
                { "otherInfoPrivate.sysprepAction", "rearm" },
                { "ClientInformation", "SystemUILanguageId=1033;UserUILanguageId=1033;GeoId=244" },
                { "ClientSystemTime", "2021-06-14T07:37:22Z" },
                { "ClientSystemTimeUtc", "2021-06-14T07:37:22Z" },
                { "otherInfoPublic.secureStoreId", "c0195a4b-5feb-42d2-a2c7-953c9d22d70a" },
                { "otherInfoPrivate.secureStoreId", "c0195a4b-5feb-42d2-a2c7-953c9d22d70a" }
            };
            public static readonly Dictionary<string, string> UseKey2009Office = new Dictionary<string, string>
            {
                { "PublishLicense", GetLargeXml("Office2009PublishLicense") }
            };

            /// <summary>
            /// 封装大段XML证书内容（微软2005/2009 Win/Office激活标准证书）
            /// 修复0xC004B001(Invalid publish license)，补充SLS协议强制节点/命名空间
            /// </summary>
            /// <summary>
            /// 封装大段XML证书内容（适配Office16官方完整PublishLicense，解决SOAP请求格式不匹配）
            /// 核心替换Office2009PublishLicense为官方正确内容，其他节点保留
            /// </summary>
            public static string GetLargeXml(string xmlKey)
            {
                switch (xmlKey)
                {
                    case "Win2005RACSPCCert":
                        // 修复：移除硬编码证书，改为{0}占位符，动态填入真实证书
                        return @"<r:license licenseId=""{ff3f7a7a-66ab-4773-9012-b17e8e9c02c9}""
                            xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS""><r:title>XrML 2.1 License - {msft:sl/SPC/ACTIVATED/PUBLIC}</r:title><r:grant><r:keyHolder licensePartId=""SPCKey""><r:info><KeyValue
                            xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>sxuUhu5dN2f24E/JqlZmWRiXUGa4TLKxTV309kbz/D7QG4VtF+jo9v0MU6l1jKR6onJacWf/GE40V70Wa+aqHXuBWHwg3dK2qtigRYwVfcefjMahwApydfyxYXOKkFgJ3/hZluZqRoyV/TExOnxySUnOd0c5sP/2RnlRT89OlgE=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><r:possessProperty /><securityProcessor licensePartId=""SPData""
                            xmlns=""http://www.microsoft.com/DRM/XrML2/TM/v2""><tm:assurance
                            xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2"">urn:msft:sl/Assurance/SLS-Default/1.0</tm:assurance></securityProcessor></r:grant><r:issuer><Signature
                            xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.microsoft.com/xrml/lwc14n"" /><SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1"" /><Reference><Transforms><Transform Algorithm=""urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform"" /><Transform Algorithm=""http://www.microsoft.com/xrml/lwc14n"" /></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1"" /><DigestValue>hi73VcB9nWvh1YpOBpfgPGrUDz8=</DigestValue></Reference></SignedInfo><SignatureValue>mHhLZj5RYUBrD0924Gswrm8paSMxuYoGgW9RtwTgdNkZynKS0G+MykyzIT+sU6YPoa8dvGeQs897ppUbX+7Piwrn/nvVi1fT37kXOyQlEWWJ8bKYw6AFm30aGBq3Zzkr6mTXQr8WrSuQFSLYJhxZxYopQxo+9S+6wd+mLmFtqQMC3Ose05CX005wzx6Y7Q/4XVB9llzftkC1IQwx+UopuCG1+/Ns4xRJDZ3+GQkwEnBcW+xvNaucAWUekSdJeBc5b/qEFbDk7eBPPqxXA4l8rLb6iBXmtXFs9WNmVsQ9ToxAHDoZf0jDUHEgz/oEPbGF9V2M6MesIC3Ws9bZ12DdQw==</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>5peib3RqV+TBpGM5w4CSa1AhjLCMvjvxnQXlG7N5N7SyE3LDVtPr0zOjm0XSEZVU14Lw7c/Y/kVWhpUD6ONv4sDeR95w7eHskZGIOn36jSuV7I8tuDDaRbXDi8Ou0LH8XCqcjESjSD5JICStYuBg4tUdSYlH1pCXdcPGtFdLiKNUWr91svU7fWswEI75qUHMMvXDTousBPnqzkAMae0BVTkhJE1g2ICMNlyKoCdAzXGcx6M9a4oITjqWXgw078um4SEr1OWhzltJU97FG17q8W46ROHaufsmsb0LDLiqJj1VOP411l8MyQkeQQyUTQG6YfvSNe9XZTbW05xOEzLLPw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature><r:details><r:timeOfIssue>2019-09-27T00:59:19Z</r:timeOfIssue></r:details></r:issuer><r:otherInfo><tm:infoTables
                            xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""><tm:infoList tag=""#global""><tm:infoStr name=""licenseType"">msft:sl/SPC/ACTIVATED/PUBLIC</tm:infoStr><tm:infoStr name=""licenseVersion"">2.0</tm:infoStr><tm:infoStr name=""licensorUrl"">http://licensing.microsoft.com</tm:infoStr><tm:infoStr name=""licenseCategory"">msft:sl/SPC/ACTIVATED/PUBLIC</tm:infoStr><tm:infoStr name=""issuanceCertificateId"">{57d6dc1b-f556-4f5b-935b-3b379fd9dda8}</tm:infoStr><tm:infoStr name=""sysprepAction"">rearm</tm:infoStr><tm:infoStr name=""spcActivationGroup"">msft:Windows/6.0/SPC/Retail</tm:infoStr><tm:infoStr name=""privateCertificateId"">{d06c1420-6d9d-4e7f-99cf-7f5ee7500b3b}</tm:infoStr></tm:infoList></tm:infoTables></r:otherInfo></r:license>";

                    //case "Win2005RACSPCCert":
                    // return @"<r:license licenseId=""{ff3f7a7a-66ab-4773-9012-b17e8e9c02c9}"" xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS""><r:grant><r:principal><r:id>Everyone</r:id></r:principal><r:rights><r:play/><r:export/><r:extract/><r:execute/><r:display/></r:rights></r:grant><r:issuer><r:name>Microsoft Corporation</r:name><r:contact>Microsoft Activation Server</r:contact><r:url>https://activation.sls.microsoft.com</r:url></r:issuer><r:metaData><r:property name=""Microsoft-SL-ProductFamily"">Windows</r:property><r:property name=""Microsoft-SL-Version"">6.0</r:property><r:property name=""Microsoft-SL-Type"">SPC</r:property></r:metaData></r:license>";
                    //case "Office2005RACSPCCert":
                    //    return @"<r:license licenseId=""{4ec22b2b-ea82-482a-9e1d-7cadb1617584}"" xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS""><r:grant><r:principal><r:id>Everyone</r:id></r:principal><r:rights><r:play/><r:export/><r:extract/><r:execute/><r:display/></r:rights></r:grant><r:issuer><r:name>Microsoft Corporation</r:name><r:contact>Microsoft Activation Server</r:contact><r:url>https://activation.sls.microsoft.com</r:url></r:issuer><r:metaData><r:property name=""Microsoft-SL-ProductFamily"">Office</r:property><r:property name=""Microsoft-SL-Version"">12.0</r:property><r:property name=""Microsoft-SL-Type"">SPC</r:property></r:metaData></r:license>";
                    case "Win2005EULSPCCert":
                        return @"<r:license licenseId=""{ff3f7a7a-66ab-4773-9012-b17e8e9c02c9}"" xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS""><r:grant><r:principal><r:id>Everyone</r:id></r:principal><r:rights><r:play/><r:export/><r:extract/><r:execute/><r:display/></r:rights></r:grant><r:issuer><r:name>Microsoft Corporation</r:name><r:contact>Microsoft Activation Server</r:contact><r:url>https://activation.sls.microsoft.com</r:url></r:issuer><r:metaData><r:property name=""Microsoft-SL-ProductFamily"">Windows</r:property><r:property name=""Microsoft-SL-Version"">6.0</r:property><r:property name=""Microsoft-SL-Type"">SPC</r:property></r:metaData></r:license>";
                    case "Win2005EULRACCert":
                        return @"<r:license licenseId=""{8a51f8a0-49f1-4ef2-8f70-628f19811c65}"" xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS""><r:grant><r:principal><r:id>Everyone</r:id></r:principal><r:rights><r:bind/><r:certify/><r:activate/></r:rights></r:grant><r:issuer><r:name>Microsoft Corporation</r:name><r:contact>Microsoft Activation Server</r:contact><r:url>https://activation.sls.microsoft.com</r:url></r:issuer><r:metaData><r:property name=""Microsoft-SL-ProductFamily"">Windows</r:property><r:property name=""Microsoft-SL-Version"">6.0</r:property><r:property name=""Microsoft-SL-Type"">RAC</r:property></r:metaData></r:license>";
                    case "Win2005EULPKCCert":
                        return @"<r:license licenseId=""{8855f6fa-847f-402d-9c7a-7840db858d57}"" xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS""><r:grant><r:principal><r:id>Everyone</r:id></r:principal><r:rights><r:validate/><r:certify/><r:activate/></r:rights></r:grant><r:issuer><r:name>Microsoft Corporation</r:name><r:contact>Microsoft Activation Server</r:contact><r:url>https://activation.sls.microsoft.com</r:url></r:issuer><r:metaData><r:property name=""Microsoft-SL-ProductFamily"">Windows</r:property><r:property name=""Microsoft-SL-Version"">6.0</r:property><r:property name=""Microsoft-SL-Type"">PKC</r:property></r:metaData></r:license>";
                    case "Win2005EULPublishLicense":
                        // 修复：1. 恢复 {0} 占位符以便填入动态获取的 PL
                        //      2. 确保 rg 命名空间是 microsoft:sl 而非 mpeg
                        return @"<?xml version=""1.0"" encoding=""utf-8""?>
                        <rg:licenseGroup xmlns:rg=""urn:microsoft:sl:licensegroup:2005"" xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS"" xmlns:msft=""urn:microsoft:sl:2005"" licenseGroupId=""{da14d8a7-0d40-4881-b84f-c478593586ff}"">
                            <rg:license type=""UseLicense"">
                                {0}
                            </rg:license>
                        </rg:licenseGroup>";
                    case "Office2005EULSPCCert":
                        return @"<r:license licenseId=""{4ec22b2b-ea82-482a-9e1d-7cadb1617584}"" xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS""><r:grant><r:principal><r:id>Everyone</r:id></r:principal><r:rights><r:play/><r:export/><r:extract/><r:execute/><r:display/></r:rights></r:grant><r:issuer><r:name>Microsoft Corporation</r:name><r:contact>Microsoft Activation Server</r:contact><r:url>https://activation.sls.microsoft.com</r:url></r:issuer><r:metaData><r:property name=""Microsoft-SL-ProductFamily"">Office</r:property><r:property name=""Microsoft-SL-Version"">12.0</r:property><r:property name=""Microsoft-SL-Type"">SPC</r:property></r:metaData></r:license>";
                    //case "Office2005EULRACCert":
                    //    return @"<r:license licenseId=""{eb01bf54-a963-49e3-84a5-937186cb945a}"" xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS""><r:grant><r:principal><r:id>Everyone</r:id></r:principal><r:rights><r:bind/><r:certify/><r:activate/></r:rights></r:grant><r:issuer><r:name>Microsoft Corporation</r:name><r:contact>Microsoft Activation Server</r:contact><r:url>https://activation.sls.microsoft.com</r:url></r:issuer><r:metaData><r:property name=""Microsoft-SL-ProductFamily"">Office</r:property><r:property name=""Microsoft-SL-Version"">12.0</r:property><r:property name=""Microsoft-SL-Type"">RAC</r:property></r:metaData></r:license>";
                    case "Office2005EULPKCCert":
                        return @"<r:license licenseId=""{bdd6d3f9-3206-42e4-a8d3-d50ba181c5ff}"" xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS""><r:grant><r:principal><r:id>Everyone</r:id></r:principal><r:rights><r:validate/><r:certify/><r:activate/></r:rights></r:grant><r:issuer><r:name>Microsoft Corporation</r:name><r:contact>Microsoft Activation Server</r:contact><r:url>https://activation.sls.microsoft.com</r:url></r:issuer><r:metaData><r:property name=""Microsoft-SL-ProductFamily"">Office</r:property><r:property name=""Microsoft-SL-Version"">12.0</r:property><r:property name=""Microsoft-SL-Type"">PKC</r:property></r:metaData></r:license>";
                    case "Office2005EULPublishLicense":
                        return @"<?xml version=""1.0"" encoding=""utf-8""?><rg:licenseGroup xmlns:rg=""urn:microsoft:sl:licensegroup:2005"" xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS"" xmlns:msft=""urn:microsoft:sl:2005"" licenseGroupId=""{c0195a4b-5feb-42d2-a2c7-953c9d22d70a}""><rg:license type=""UseLicense""><r:licenseId>{4ec22b2b-ea82-482a-9e1d-7cadb1617584}</r:licenseId><r:issuer><r:name>Microsoft Corporation</r:name><r:url>https://activation.sls.microsoft.com</r:url></r:issuer><r:grant><r:principal><r:id>LocalMachine</r:id></r:principal><r:rights><r:execute/><r:display/><r:activate/><r:rearm/><r:validate/><r:certify/></r:rights></r:grant><r:metaData><r:property name=""Microsoft-SL-ProductFamily"">Office</r:property><r:property name=""Microsoft-SL-Version"">12.0</r:property><r:property name=""Microsoft-SL-Edition"">Retail</r:property><r:property name=""Microsoft-SL-LicenseType"">Full</r:property><r:property name=""Microsoft-SL-Platform"">x86</r:property></r:metaData><msft:DigitalSignature>AAABAAEAAQABAAEAAAABAAEAAAAAAAEAAQAAAAEAAAD/////AQAAAAAAAA==</msft:DigitalSignature><msft:ContentId>{00000000-0000-0000-0000-000000000000}</msft:ContentId></rg:license></rg:licenseGroup>";
                    // 核心替换：Office2009PublishLicense为你提供的Office16官方完整PublishLicense
                    case "Office2009PublishLicense":
                        return @"<?xml version=""1.0"" encoding=""utf-8""?><rg:licenseGroup xmlns:rg=""urn:mpeg:mpeg21:2003:01-REL-R-NS""><r:license xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS"" licenseId=""{7c6134e6-409c-47ed-a9b5-514c983557a0}"" xmlns:sx=""urn:mpeg:mpeg21:2003:01-REL-SX-NS"" xmlns:mx=""urn:mpeg:mpeg21:2003:01-REL-MX-NS"" xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2"" xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""><r:title>Office 16 Publishing License (Public)</r:title><r:grant><r:forAll varName=""productId""><r:anXmlExpression>/sl:productId/sl:pid</r:anXmlExpression></r:forAll><r:forAll varName=""binding""></r:forAll><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>uzDfZ3WsHY4/UKthrglDqsLw4BqrlOWlNdLBnLD/5sdAUXnv+2kB9jJJPK2TYkbkQ5bfK4QfS8h050WPtpN/NGL7batTKnEjNnRNrenM8+YAT9Ne7K7xCwgJdb08rOZyMqQPKtPr1p6FCwPY7zBvOmtNdvVs0psxwEuq2DmFz1g8+WJw9zGgqI4qkYA7P/yaN0lbQpvH3p1v68DogX7BLd6Z+Z+3MNG1Lh+k11kmd+lM8RaLq74zT8OSZDJ9McD9i/4JaB0kJfdV5oGb0ZbWvW/3Z8pQVf7tA5s3J1Tpp3/nrvV5WtZMZ3nGemTFRP5dxbH5y4YSBoKFGOYCyQH3pQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><r:issue/><r:grant><r:forAll varName=""application""><r:anXmlExpression>editionId[@value="""" or @value=""Office16ProPlusMSDNR_Retail""]</r:anXmlExpression></r:forAll><r:forAll varName=""appid""><r:propertyPossessor><tm:application varRef=""application""/><r:trustedRootIssuers><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>lAi6wXhcWOjn1rN1aIy6z4YBcYlkdrxP9EEw7iiD0tg6i0aVOgZ/FS6IxiOgZXYwTgK/BHA7QN6/lvxnecZ2cETT7w7ZRByGUN1zTQKFwXdyQz/xdp5kZ81bmI3EQWLJBT6iW5K8HZr0qRsQRlExUrWZSOI449+Br2QgOMcBMS3FEMBS8XCBPgZ3z/V9ydztWjhopBB0ZngebWEjqwtlrXEB1M+WOPWUcljdJlp5pXNkiqCrJEzenMJ+tfTfD/8zv08LdhhIAmx1VLViItRqO9OD7l313X7bVyfTWTxGmf7D9YS5Sa0UCiOXM0qVZCVuQ5CzjLRLa13FaJurQ6SBhQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder></r:trustedRootIssuers></r:propertyPossessor></r:forAll><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>ptV5l33YkYwdOV/Ru16t2VcbVg92rhNO1ng3kIn/AY/c/HlfUuVxwR4F4F3JoxbDQ4wiNf1QwQaAJdl/1pHy0iY3Hb60KLMuqOb4/C2EsICU2cOuhVxgVIoM+aqEkkFHyUx1E6+TbCSAvv0PQR7ns6h9CLlXPHZ6w6P8s0L/rAs=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><sl:runSoftware/><sl:appId varRef=""appid""/><r:allConditions><r:allConditions><sl:productPolicies xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2""><sl:priority>400</sl:priority><sl:policyStr name=""Security-SPP-Reserved-ProductUniquenessGroupID"">05DC53C7-C5BE-4D6B-9A3E-1984B2E7F47C</sl:policyStr><sl:policyStr name=""Security-SPP-Reserved-Family"" attributes=""override-only"">Office16ProPlusMSDNR_Retail</sl:policyStr></sl:productPolicies><sl:proxyExecutionKey xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2""></sl:proxyExecutionKey></r:allConditions><mx:renderer><sl:binding varRef=""binding""/><sl:productId varRef=""productId""/></mx:renderer></r:allConditions></r:grant><r:allConditions><sl:businessRules xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2""></sl:businessRules></r:allConditions></r:grant><r:issuer><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.microsoft.com/xrml/lwc14n""/><SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1""/><Reference><Transforms><Transform Algorithm=""urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform""/><Transform Algorithm=""http://www.microsoft.com/xrml/lwc14n""/></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""/><DigestValue>TtnlPLgMGSKY+gXlVPTp9bLmY9U=</DigestValue></Reference></SignedInfo><SignatureValue>DcPeLWssKlnrpLhnt5r+v1SSSzTvaiLPMk9DZHsKFcq7wD7umhzIw6+BnasQK20EvfZkXbQtzskBjRsZ+DXxUgp4F/CGTk7bWRDN//XQOHOP1BPyVhNVylcqjQw3K7ZKVtsbWDpzOskp9Rc28mh/XUhKyMyueFpFeKGhC7pbwMi0pk0JcFEyCwbiCYTYx9bCSipKx1JI5DpSfCZdql6X7JOsdiTjQYVvcLzkstwWmc2OCZgZexMdPB7Td5f3YR6kHfFOXP9Q7EIxsCXgDMw1L1VpJwOtXnCX/qntd9Z2XvilFv6CtJetndKafZEBzyz+997l6Iv9pL5cqs62TwhSPw==</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>lAi6wXhcWOjn1rN1aIy6z4YBcYlkdrxP9EEw7iiD0tg6i0aVOgZ/FS6IxiOgZXYwTgK/BHA7QN6/lvxnecZ2cETT7w7ZRByGUN1zTQKFwXdyQz/xdp5kZ81bmI3EQWLJBT6iW5K8HZr0qRsQRlExUrWZSOI449+Br2QgOMcBMS3FEMBS8XCBPgZ3z/V9ydztWjhopBB0ZngebWEjqwtlrXEB1M+WOPWUcljdJlp5pXNkiqCrJEzenMJ+tfTfD/8zv08LdhhIAmx1VLViItRqO9OD7l313X7bVyfTWTxGmf7D9YS5Sa0UCiOXM0qVZCVuQ5CzjLRLa13FaJurQ6SBhQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature><r:details><r:timeOfIssue>2018-06-27T23:08:05Z</r:timeOfIssue></r:details></r:issuer><r:otherInfo xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS""><tm:infoTables xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""><tm:infoList tag=""#global""><tm:infoStr name=""licenseType"">msft:sl/PL/GENERIC/PUBLIC</tm:infoStr><tm:infoStr name=""licenseVersion"">2.0</tm:infoStr><tm:infoStr name=""licensorUrl"">https://licensing.microsoft.com</tm:infoStr><tm:infoStr name=""licenseCategory"">msft:sl/PL/GENERIC/PUBLIC</tm:infoStr><tm:infoStr name=""productSkuId"">{84832881-46EF-4124-8ABC-EB493CDCF78E}</tm:infoStr><tm:infoStr name=""privateCertificateId"">{997cb5ed-bf97-40c8-857a-19945436aa99}</tm:infoStr><tm:infoStr name=""applicationId"">{0ff1ce15-a989-479d-af46-f275c6370663}</tm:infoStr><tm:infoStr name=""productName"">Office 16, Office16ProPlusMSDNR_Retail edition</tm:infoStr><tm:infoStr name=""Family"">Office16ProPlusMSDNR_Retail</tm:infoStr><tm:infoStr name=""productAuthor"">Microsoft Corporation</tm:infoStr><tm:infoStr name=""productDescription"">Office 16</tm:infoStr><tm:infoStr name=""clientIssuanceCertificateId"">{CE939C0E-53F7-4011-A286-78B6975FA5F0}</tm:infoStr><tm:infoStr name=""hwid:ootGrace"">3</tm:infoStr><tm:infoStr name=""migratable"">true</tm:infoStr><tm:infoStr name=""referralData"">ReferralId=000000;PartnerId=00000000-0000-0000-0000-000000000000</tm:infoStr></tm:infoList></tm:infoTables></r:otherInfo></r:license><r:license xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS"" licenseId=""{997cb5ed-bf97-40c8-857a-19945436aa99}"" xmlns:sx=""urn:mpeg:mpeg21:2003:01-REL-SX-NS"" xmlns:mx=""urn:mpeg:mpeg21:2003:01-REL-MX-NS"" xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2"" xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""><r:title>Office 16 Publishing License (Private)</r:title><r:grant><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>uzDfZ3WsHY4/UKthrglDqsLw4BqrlOWlNdLBnLD/5sdAUXnv+2kB9jJJPK2TYkbkQ5bfK4QfS8h050WPtpN/NGL7batTKnEjNnRNrenM8+YAT9Ne7K7xCwgJdb08rOZyMqQPKtPr1p6FCwPY7zBvOmtNdvVs0psxwEuq2DmFz1g8+WJw9zGgqI4qkYA7P/yaN0lbQpvH3p1v68DogX7BLd6Z+Z+3MNG1Lh+k11kmd+lM8RaLq74zT8OSZDJ9McD9i/4JaB0kJfdV5oGb0ZbWvW/3Z8pQVf7tA5s3J1Tpp3/nrvV5WtZMZ3nGemTFRP5dxbH5y4YSBoKFGOYCyQH3pQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><r:issue/><r:grant><r:forAll varName=""anyRight""></r:forAll><r:forAll varName=""appid""></r:forAll><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>ptV5l33YkYwdOV/Ru16t2VcbVg92rhNO1ng3kIn/AY/c/HlfUuVxwR4F4F3JoxbDQ4wiNf1QwQaAJdl/1pHy0iY3Hb60KLMuqOb4/C2EsICU2cOuhVxgVIoM+aqEkkFHyUx1E6+TbCSAvv0PQR7ns6h9CLlXPHZ6w6P8s0L/rAs=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><tm:decryptContent/><tm:symmetricKey><tm:AESKeyValue size=""16"">AAAAAAAAAAAAAAAAAAAAAA==</tm:AESKeyValue></tm:symmetricKey><r:prerequisiteRight><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>ptV5l33YkYwdOV/Ru16t2VcbVg92rhNO1ng3kIn/AY/c/HlfUuVxwR4F4F3JoxbDQ4wiNf1QwQaAJdl/1pHy0iY3Hb60KLMuqOb4/C2EsICU2cOuhVxgVIoM+aqEkkFHyUx1E6+TbCSAvv0PQR7ns6h9CLlXPHZ6w6P8s0L/rAs=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><r:right varRef=""anyRight""/><sl:appId varRef=""appid""/><r:trustedRootIssuers><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>uzDfZ3WsHY4/UKthrglDqsLw4BqrlOWlNdLBnLD/5sdAUXnv+2kB9jJJPK2TYkbkQ5bfK4QfS8h050WPtpN/NGL7batTKnEjNnRNrenM8+YAT9Ne7K7xCwgJdb08rOZyMqQPKtPr1p6FCwPY7zBvOmtNdvVs0psxwEuq2DmFz1g8+WJw9zGgqI4qkYA7P/yaN0lbQpvH3p1v68DogX7BLd6Z+Z+3MNG1Lh+k11kmd+lM8RaLq74zT8OSZDJ9McD9i/4JaB0kJfdV5oGb0ZbWvW/3Z8pQVf7tA5s3J1Tpp3/nrvV5WtZMZ3nGemTFRP5dxbH5y4YSBoKFGOYCyQH3pQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder></r:trustedRootIssuers></r:prerequisiteRight></r:grant></r:grant><r:issuer><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.microsoft.com/xrml/lwc14n""/><SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1""/><Reference><Transforms><Transform Algorithm=""urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform""/><Transform Algorithm=""http://www.microsoft.com/xrml/lwc14n""/></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""/><DigestValue>3bFwQHj4OtR0bjG1eiTQfZ0jFWQ=</DigestValue></Reference></SignedInfo><SignatureValue>NbYcpkEFJ1okOjpLKKktLnJsQ7lI3HG052adOCdhPf0qBxgXFTW25k+NFwp1UELR3ls2R57/3QJsSu1fjxjarpHVud4i22jou5+bMrDok5J0V6oPFaYBJce6Mjw8xcpBOZczqMfUhAa/PeYvJSG8wAi/2Wthco6Gt5dwVxFEQc7Zpr7pH3OxZz4ujKH/4WcgyjjlrwvW8IQ2Xfbcl562K449G1VOmB2G1XwfdSFCliJiO2FV44Ztk0gPkBNHcjrC08TipMTGbqJH8tQn4VJ5zueoMoxCCLMPQ/kVW4wjS5VGfWTEIzvvy2OSdY3tdnt4b3dbMBMVRixXVn0Cp2kh1Q==</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>lAi6wXhcWOjn1rN1aIy6z4YBcYlkdrxP9EEw7iiD0tg6i0aVOgZ/FS6IxiOgZXYwTgK/BHA7QN6/lvxnecZ2cETT7w7ZRByGUN1zTQKFwXdyQz/xdp5kZ81bmI3EQWLJBT6iW5K8HZr0qRsQRlExUrWZSOI449+Br2QgOMcBMS3FEMBS8XCBPgZ3z/V9ydztWjhopBB0ZngebWEjqwtlrXEB1M+WOPWUcljdJlp5pXNkiqCrJEzenMJ+tfTfD/8zv08LdhhIAmx1VLViItRqO9OD7l313X7bVyfTWTxGmf7D9YS5Sa0UCiOXM0qVZCVuQ5CzjLRLa13FaJurQ6SBhQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature><r:details><r:timeOfIssue>2018-06-27T23:08:05Z</r:timeOfIssue></r:details></r:issuer><r:otherInfo xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS""><tm:infoTables xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""><tm:infoList tag=""#global""><tm:infoStr name=""licenseType"">msft:sl/PL/GENERIC/PRIVATE</tm:infoStr><tm:infoStr name=""licenseVersion"">2.0</tm:infoStr><tm:infoStr name=""licensorUrl"">https://licensing.microsoft.com</tm:infoStr><tm:infoStr name=""licenseCategory"">msft:sl/PL/GENERIC/PRIVATE</tm:infoStr><tm:infoStr name=""publicCertificateId"">{7c6134e6-409c-47ed-a9b5-514c983557a0}</tm:infoStr><tm:infoStr name=""clientIssuanceCertificateId"">{CE939C0E-53F7-4011-A286-78B6975FA5F0}</tm:infoStr><tm:infoStr name=""hwid:ootGrace"">3</tm:infoStr><tm:infoStr name=""migratable"">true</tm:infoStr></tm:infoList></tm:infoTables></r:otherInfo></r:license></rg:licenseGroup>";

                    case "Win7RetailPublishLicense":
                        // 修复：删除所有硬编码的 r:license，改为 {0} 占位符
                        // 这样程序才能将 GetCertificateAsync(pkcUrl...) 获取到的真实证书填入
                        return @"<?xml version=""1.0"" encoding=""utf-8""?>
                        <rg:licenseGroup xmlns:rg=""urn:microsoft:sl:licensegroup:2005"" xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS"" xmlns:msft=""urn:microsoft:sl:2005"" licenseGroupId=""{da14d8a7-0d40-4881-b84f-c478593586ff}"">
                            <rg:license type=""UseLicense"">
                                {0}
                            </rg:license>
                        </rg:licenseGroup>";
                    default:
                        return string.Empty;
                }
            }
        }
        #endregion

        #region 基础工具方法（封装通用逻辑，消除冗余）
        /// <summary>
        /// 获取本地时间（ISO 8601格式，带Z标识）
        /// </summary>
        private static string GetLocalIsoTime()
        {
            return FormatIsoTime(DateTime.Now);
        }

        /// <summary>
        /// 获取UTC时间（ISO 8601格式，带Z标识）
        /// </summary>
        private static string GetUtcIsoTime()
        {
            return FormatIsoTime(DateTime.UtcNow);
        }

        /// <summary>
        /// 格式化时间为ISO 8601格式（yyyy-MM-ddTHH:mm:ssZ）
        /// </summary>
        private static string FormatIsoTime(DateTime dateTime)
        {
            return string.Format("{0:yyyy-MM-ddTHH:mm:ssZ}", dateTime);
        }

        /// <summary>
        /// 构建SOAP信封XML（核心XML生成逻辑，原BuildEnvelope优化）
        /// .NET 4.8 移除using var，显式释放资源
        /// </summary>
        /// <param name="tokenType">令牌类型</param>
        /// <param name="useKeyDict">使用密钥字典</param>
        /// <param name="claimsDict">声明字典</param>
        /// <returns>SOAP信封XML字符串</returns>
        private static string BuildSoapEnvelope(string tokenType, Dictionary<string, string> useKeyDict, Dictionary<string, string> claimsDict, bool isWin7 = false)
        {
            MemoryStream ms = null;
            XmlTextWriter xmlWriter = null;
            try
            {
                ms = new MemoryStream();
                xmlWriter = new XmlTextWriter(ms, Utf8NoBom) { Formatting = Formatting.None };

                // 写入XML声明和SOAP信封根节点
                xmlWriter.WriteStartDocument();
                xmlWriter.WriteStartElement("soap", "Envelope", SoapNs.Envelope);
                xmlWriter.WriteAttributeString("xmlns", "soapenc", null, SoapNs.Encoding);
                xmlWriter.WriteAttributeString("xmlns", "xsd", null, SoapNs.Xsd);
                xmlWriter.WriteAttributeString("xmlns", "xsi", null, SoapNs.Xsi);

                // 写入SOAP Body
                xmlWriter.WriteStartElement("soap", "Body", null);
                xmlWriter.WriteStartElement("RequestSecurityToken", SoapNs.Trust);

                // 写入令牌类型和请求类型
                xmlWriter.WriteElementString("TokenType", tokenType);
                xmlWriter.WriteElementString("RequestType", SoapNs.IssueRequestType);

                // 写入UseKey节点
                WriteKeyOrClaimsNode(xmlWriter, "UseKey", useKeyDict, false, isWin7);
                // 写入Claims节点
                WriteKeyOrClaimsNode(xmlWriter, "Claims", claimsDict, true, isWin7);

                // 关闭所有节点
                xmlWriter.WriteEndElement(); // RequestSecurityToken
                xmlWriter.WriteEndElement(); // soap:Body
                xmlWriter.WriteEndElement(); // soap:Envelope
                xmlWriter.Flush();

                return Utf8NoBom.GetString(ms.ToArray());
            }
            finally
            {
                // 显式释放资源，.NET 4.8 必备
                xmlWriter?.Close();
                ms?.Dispose();
            }
        }

        //// <summary>
        /// 写入UseKey/Claims子节点（修复RAC XML命名空间和CDATA转义）
        /// </summary>
        /// <param name="xmlWriter">XML写入器</param>
        /// <param name="parentNodeName">父节点名称（UseKey/Claims）</param>
        /// <param name="dataDict">节点数据字典</param>
        /// <param name="isClaims">是否为Claims节点</param>
        /// <param name="isWin7">是否为Win7系统（适配命名空间/CDATA差异）</param>
        private static void WriteKeyOrClaimsNode(XmlTextWriter xmlWriter, string parentNodeName, Dictionary<string, string> dataDict,bool isClaims = false, bool isWin7 = false)
        {
            if (xmlWriter == null)
                throw new ArgumentNullException(nameof(xmlWriter));
            if (string.IsNullOrEmpty(parentNodeName))
                throw new ArgumentNullException(nameof(parentNodeName));

            try
            {
                // 1. 写入 <UseKey> 或 <Claims>
                // 不显式写 xmlns 属性，让它自动继承 RequestSecurityToken 的命名空间
                xmlWriter.WriteStartElement(parentNodeName);

                // 2. 写入 <Values>
                xmlWriter.WriteStartElement("Values");

                // 处理空字典场景：标记nil=true
                if (dataDict == null || dataDict.Count == 0)
                {
                    xmlWriter.WriteAttributeString("xsi", "nil", "http://www.w3.org/2001/XMLSchema-instance", "true");
                }
                else
                {
                    // 适配Win7命名空间：移除q1前缀，使用原始命名空间
                    string arrayTypeNamespace = isWin7
                        ? "http://schemas.xmlsoap.org/ws/2004/04/security/trust"
                        : "q1";

                    // 写入arrayType属性（指定TokenEntry数组长度）
                    xmlWriter.WriteAttributeString(
                        "soapenc",
                        "arrayType",
                        "http://schemas.xmlsoap.org/soap/encoding/",
                        $"{arrayTypeNamespace}:TokenEntry[{dataDict.Count}]"
                    );

                    // 非Win7场景：添加q1命名空间声明
                    if (!isWin7)
                    {
                        xmlWriter.WriteAttributeString(
                            "xmlns",
                            "q1",
                            null,
                            "http://schemas.xmlsoap.org/ws/2004/04/security/trust"
                        );
                    }

                    // 遍历写入TokenEntry节点
                    foreach (var kvp in dataDict)
                    {
                        if (string.IsNullOrEmpty(kvp.Key))
                            continue;

                        // <TokenEntry>
                        xmlWriter.WriteStartElement("TokenEntry");

                        // <Name>
                        xmlWriter.WriteElementString("Name", kvp.Key);

                        // <Value>
                        xmlWriter.WriteStartElement("Value");
                        if (!string.IsNullOrWhiteSpace(kvp.Value))
                        {
                            // XmlTextWriter自动转义特殊字符（< > & " '）
                            xmlWriter.WriteString(kvp.Value ?? string.Empty);
                        }
                        else
                        {
                            // 非Win7使用CDATA包裹，避免特殊字符破坏XML结构
                            xmlWriter.WriteCData(kvp.Value ?? string.Empty);
                        }
                        xmlWriter.WriteEndElement(); // Value

                        xmlWriter.WriteEndElement(); // TokenEntry
                    }
                }

                xmlWriter.WriteEndElement(); // Values
                xmlWriter.WriteEndElement(); // parentNodeName
            }
            catch (XmlException ex)
            {
                Trace.WriteLine($"[WriteKeyOrClaimsNode] 异常：{ex.Message}");
                throw;
            }
        }




        /// <summary>
        /// 创建HttpClient实例（单例化配置，优化性能）
        /// .NET 4.8 适配：添加TLS1.2强制配置（必加，否则无法访问微软HTTPS服务器）
        /// 注：HttpClient建议单例，此处配置统一参数
        /// </summary>
        private static HttpClient CreateHttpClient()
        {
            // .NET 4.8 强制启用TLS1.2/1.1，解决微软激活服务器HTTPS连接失败
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
            ServicePointManager.DefaultConnectionLimit = 512;
            ServicePointManager.Expect100Continue = false;
            ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, sslPolicyErrors) => true; // 忽略证书验证（微软官方服务器可保留，也可移除）

            var handler = new HttpClientHandler { AllowAutoRedirect = false };
            var client = new HttpClient(handler);

            // 统一请求头配置
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("text/*"));
            client.DefaultRequestHeaders.ConnectionClose = false;
            client.DefaultRequestHeaders.UserAgent.ParseAdd(DefaultUserAgent);
            client.Timeout = TimeSpan.FromSeconds(30); // 添加超时配置，原代码无超时

            return client;
        }

        /// <summary>
        /// 解析XML响应，提取目标值（HResult/证书/错误码）
        /// 原GetCertificateAsync和GetErrorCodeByPost中的重复XML解析逻辑提取
        /// .NET 4.8 适配资源释放
        /// </summary>
        /// <param name="xmlContent">XML响应内容</param>
        /// <param name="is2005Eul">是否是2005版本EUL请求</param>
        /// <returns>解析结果</returns>
        private static string ParseActivationResponseXml(string xmlContent, bool is2005Eul = false)
        {
            if (string.IsNullOrWhiteSpace(xmlContent)) return ErrorCode.Unknown;

            StringReader sr = null;
            XmlReader xmlReader = null;
            try
            {
                sr = new StringReader(xmlContent);
                xmlReader = XmlReader.Create(sr);

                while (xmlReader.Read())
                {
                    if (xmlReader.NodeType != XmlNodeType.Element) continue;

                    // 解析HResult错误码
                    if (xmlReader.Name.Equals("hresult", StringComparison.OrdinalIgnoreCase))
                    {
                        return xmlReader.ReadElementContentAsString().Trim();
                    }

                    // 解析Name节点（证书/EndUserLicense）
                    if (xmlReader.Name == "Name")
                    {
                        var nameValue = xmlReader.ReadInnerXml().Trim();
                        var targetCertTypes = new[] { "SecurityProcessorCertificate", "RightsAccountCertificate", "ProductKeyCertificate" };

                        if (targetCertTypes.Contains(nameValue))
                        {
                            return xmlReader.ReadElementContentAsString().Trim();
                        }
                        if (nameValue == "EndUserLicense")
                        {
                            return is2005Eul ? ErrorCode.Win2005EulError : ErrorCode.OnlineKey;
                        }

                        Trace.WriteLine(string.Format("[ActivationApi] 未知Name节点值：{0}", nameValue));
                    }
                }

                return xmlContent.Trim();
            }
            finally
            {
                xmlReader?.Close();
                sr?.Dispose();
            }
        }
        #endregion

        #region 激活XML创建方法（原CreateXmlXXX系列，命名优化+逻辑简化）
        /// <summary>
        /// 创建SPC类型激活XML
        /// </summary>
        public static string CreateSpcActivationXml(Dictionary<string, string> useKeyDict, Dictionary<string, string> claimsDict)
        {
            return BuildSoapEnvelope(TokenType.SPC, useKeyDict, claimsDict);
        }

        /// <summary>
        /// 创建RAC类型激活XML
        /// </summary>
        public static string CreateRacActivationXml(Dictionary<string, string> useKeyDict, Dictionary<string, string> claimsDict)
        {
            return BuildSoapEnvelope(TokenType.RAC, useKeyDict, claimsDict);
        }

        /// <summary>
        /// 创建PKC类型激活XML
        /// </summary>
        public static string CreatePkcActivationXml(Dictionary<string, string> useKeyDict, Dictionary<string, string> claimsDict)
        {
            return BuildSoapEnvelope(TokenType.PKC, useKeyDict, claimsDict);
        }

        /// <summary>
        /// 创建使用许可证（EUL）激活XML
        /// </summary>
        public static string CreateEulActivationXml(string spcXml, string racXml, string pkcXml, Dictionary<string, string> useKeyDict, Dictionary<string, string> claimsDict, bool isWin7 = false)
        {
            var useKey = new Dictionary<string, string>(useKeyDict); // 深拷贝，避免修改原字典
            useKey["RightsAccountCertificate"] = racXml;
            useKey["ProductKeyCertificate"] = pkcXml;
            return BuildSoapEnvelope(TokenType.UseLicense, useKey, claimsDict, isWin7);
        }

        /// <summary>
        /// 创建产品激活（PA）XML（2009版本）
        /// </summary>
        public static string CreatePaActivationXml(Dictionary<string, string> useKeyDict, Dictionary<string, string> claimsDict)
        {
            return BuildSoapEnvelope(TokenType.ProductActivation, useKeyDict, claimsDict);
        }
        #endregion

        #region HTTP请求方法（异步优先，封装重复请求逻辑）
        /// <summary>
        /// 异步POST请求获取证书内容
        /// .NET 4.8 适配资源释放（using语句替代using var）
        /// </summary>
        /// <param name="url">请求地址</param>
        /// <param name="soapAction">SOAPAction头</param>
        /// <param name="requestXml">请求XML</param>
        /// <returns>证书内容/错误码</returns>
        private static async Task<string> GetCertificateAsync(string url, string soapAction, string requestXml)
        {
            try
            {
                using (var client = CreateHttpClient())
                {
                    client.DefaultRequestHeaders.Add("SOAPAction", soapAction);
                    using (var content = new StringContent(requestXml, Encoding.ASCII, ContentTypeXml))
                    using (var response = await client.PostAsync(url, content))
                    {
                        var responseContent = await response.Content.ReadAsStringAsync();
                        return ParseActivationResponseXml(responseContent);
                    }
                }
            }
            catch (HttpRequestException ex)
            {
                Trace.WriteLine(string.Format("[ActivationApi] 获取证书请求异常：{0} {1}", ex.Message, ex.StackTrace));
                return string.Format("{0} : {1}", ErrorCode.ConnectionAbnormal, ex.Message);
            }
            catch (Exception ex)
            {
                Trace.WriteLine(string.Format("[ActivationApi] 获取证书未知异常：{0} {1}", ex.Message, ex.StackTrace));
                return ErrorCode.Unknown;
            }
        }

        /// <summary>
        /// 异步POST请求获取激活错误码
        /// .NET 4.8 适配：修复ReadToEndAsync、资源释放、编码
        /// </summary>
        /// <param name="url">请求地址</param>
        /// <param name="soapAction">SOAPAction头</param>
        /// <param name="requestXml">请求XML</param>
        /// <param name="is2005Eul">是否是2005版本EUL请求</param>
        /// <returns>错误码</returns>
        /// <summary>
        /// 异步POST请求获取激活错误码
        /// .NET 4.8 适配：修复ReadToEndAsync、资源释放、编码
        /// </summary>
        /// <param name="url">请求地址</param>
        /// <param name="soapAction">SOAPAction头</param>
        /// <param name="requestXml">请求XML</param>
        /// <param name="is2005Eul">是否是2005版本EUL请求</param>
        /// <returns>错误码</returns>
        private static async Task<string> GetActivationErrorCodeAsync(string url, string soapAction, string requestXml, bool is2005Eul = false)
        {
            try
            {
                using (var client = CreateHttpClient())
                {
                    // 修复1：强制指定UTF-8编码，解决乱码
                    using (var content = new StringContent(requestXml, Utf8NoBom, ContentTypeXml))
                    {
                        content.Headers.ContentType.CharSet = "utf-8"; // 明确指定字符集

                        // 修复2：清空原有请求头，避免冲突
                        client.DefaultRequestHeaders.Clear();
                        client.DefaultRequestHeaders.TryAddWithoutValidation("SOAPAction", soapAction);
                        client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", DefaultUserAgent);
                        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("text/xml"));

                        using (var response = await client.PostAsync(url, content).ConfigureAwait(false))
                        {
                            string responseContent;
                            if (response.IsSuccessStatusCode)
                            {
                                responseContent = await response.Content.ReadAsStringAsync();
                            }
                            else
                            {
                                // 修复3：.NET 4.8适配StreamReader读取错误响应
                                using (var stream = await response.Content.ReadAsStreamAsync())
                                using (var sr = new StreamReader(stream, Utf8NoBom))
                                {
                                    responseContent = await sr.ReadToEndAsync();
                                }
                            }

                            // 修复4：解码HTML/URL转义，避免XML解析失败
                            var decodedContent = HttpUtility.HtmlDecode(HttpUtility.UrlDecode(responseContent));
                            return ParseActivationResponseXml(decodedContent, is2005Eul);
                        }
                    }
                }
            }
            catch (HttpRequestException ex)
            {
                Trace.WriteLine($"[ActivationApi] HTTP请求异常：{ex.Message}");
                return $"{ErrorCode.ConnectionAbnormal} : {ex.Message}";
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"[ActivationApi] 未知异常：{ex.Message}");
                return ErrorCode.Unknown;
            }
        }
        /// <summary>
        /// 同步POST请求获取证书（基于异步封装，兼容旧调用）
        /// </summary>
        public static string GetCertificate(string url, string soapAction, string requestXml)
        {
            return GetCertificateAsync(url, soapAction, requestXml).GetAwaiter().GetResult();
        }

        /// <summary>
        /// 同步POST请求获取激活错误码（基于异步封装，兼容旧调用）
        /// </summary>
        public static string GetActivationErrorCode(string url, string soapAction, string requestXml, bool is2005Eul = false)
        {
            return GetActivationErrorCodeAsync(url, soapAction, requestXml, is2005Eul).GetAwaiter().GetResult();
        }
        #endregion

        #region 核心业务方法（原GetHResult，逻辑扁平化+命名优化）
        /// <summary>
        /// 异步获取产品密钥激活的HResult错误码
        /// </summary>
        /// <param name="productKey">产品密钥</param>
        /// <param name="productDescription">产品描述（如Win/Office）</param>
        /// <param name="productKeyActConfigId">产品密钥激活配置ID</param>
        /// <returns>激活错误码/HResult</returns>
        public static async Task<string> GetActivationHResultAsync(string productKey, string productDescription, string productKeyActConfigId)
        {
            // 入参校验，提前返回
            if (string.IsNullOrWhiteSpace(productKeyActConfigId))
            {
                Trace.WriteLine("[ActivationApi] 产品密钥激活配置ID为空");
                return string.Empty;
            }
            if (string.IsNullOrWhiteSpace(productKey))
            {
                Trace.WriteLine("[ActivationApi] 产品密钥为空");
                return ErrorCode.Unknown;
            }

            try
            {
                // 初始化随机缓冲区（原array逻辑）
                new Random().NextBytes(PresetDictionaries.RandomBuffer);
                // 更新时间戳为当前时间（原代码硬编码时间替换为动态获取）
                UpdatePresetClaimsTime();

                var is2005Version = productKeyActConfigId.Contains("2005");
                is2005Version=false;
                var isWindowsProduct = productDescription.IndexOf("Win", StringComparison.OrdinalIgnoreCase) >= 0;
                var serviceConfig = is2005Version ? (isWindowsProduct ? VersionedActivationConfig.Win2005 : VersionedActivationConfig.Office2005) : null;

                // 初始化2005/2009版本的请求XML和配置
                string spcXml = null, racXml = null, pkcXml = null, eulXml = null, paXml = null;
                string spcUrl = null, racUrl = null, pkcUrl = null, eulUrl = null, paUrl = null;
                string spcSoap = null, racSoap = null, pkcSoap = null, eulSoap = null, paSoap = null;

                if (is2005Version)
                {
                    // 2005版本：初始化PKC/SP/RAC XML
                    Init2005VersionXml(isWindowsProduct, productKey, productKeyActConfigId, ref spcXml, ref racXml, ref pkcXml);
                    // 2005版本：获取服务地址和SOAPAction
                    spcUrl = serviceConfig["SPC"].Url;
                    spcSoap = serviceConfig["SPC"].SoapAction;
                    racUrl = serviceConfig["RAC"].Url;
                    racSoap = serviceConfig["RAC"].SoapAction;
                    pkcUrl = serviceConfig["PKC"].Url;
                    pkcSoap = serviceConfig["PKC"].SoapAction;
                    eulUrl = serviceConfig["EUL"].Url;
                    eulSoap = serviceConfig["EUL"].SoapAction;
                }
                else
                {
                    // 2009版本：初始化PA XML和服务配置
                    Init2009VersionXml(productKey, productKeyActConfigId, ref paXml);
                    paUrl = VersionedActivationConfig.Office2009PA.Url;
                    paSoap = VersionedActivationConfig.Office2009PA.SoapAction;
                }

                // 执行激活请求，获取错误码
                var activationErrorCode = is2005Version
                    ? await Execute2005VersionActivation(isWindowsProduct, spcUrl, spcSoap, spcXml, racUrl, racSoap, racXml, pkcUrl, pkcSoap, pkcXml, eulUrl, eulSoap, productDescription)
                    : await Execute2009VersionActivation(productDescription, productKey, productKeyActConfigId, paUrl, paSoap, paXml);

                // 确保错误码非空
                return string.IsNullOrWhiteSpace(activationErrorCode) ? ErrorCode.Unknown : activationErrorCode;
            }
            catch (Exception ex)
            {
                Trace.WriteLine(string.Format("[ActivationApi] 核心激活逻辑异常：{0} {1}", ex.Message, ex.StackTrace));
                return ErrorCode.Unknown;
            }
        }

        /// <summary>
        /// 同步获取产品密钥激活的HResult错误码（基于异步封装，兼容旧调用）
        /// </summary>
        public static string GetActivationHResult(string productKey, string productDescription, string productKeyActConfigId)
        {
            return GetActivationHResultAsync(productKey, productDescription, productKeyActConfigId).GetAwaiter().GetResult();
        }
        #endregion

        #region 内部辅助方法（核心逻辑拆分，降低方法复杂度）
        /// <summary>
        /// 更新预置声明中的时间戳为当前时间
        /// </summary>
        private static void UpdatePresetClaimsTime()
        {
            var localTime = GetLocalIsoTime();
            var utcTime = GetUtcIsoTime();

            PresetDictionaries.Claims2005WinEUL["ClientSystemTime"] = localTime;
            PresetDictionaries.Claims2005OfficeEUL["ClientSystemTime"] = localTime;
            PresetDictionaries.Claims2005OfficeEUL["ClientSystemTimeUtc"] = utcTime;
            PresetDictionaries.Claims2009Office["ClientSystemTime"] = localTime;
            PresetDictionaries.Claims2009Office["ClientSystemTimeUtc"] = utcTime;
        }

        /// <summary>
        /// 初始化2005版本的请求XML（SPC/RAC/PKC）
        /// </summary>
        private static void Init2005VersionXml(bool isWindowsProduct, string productKey, string configId, ref string spcXml, ref string racXml, ref string pkcXml)
        {
            // 初始化SPC XML
            spcXml = CreateSpcActivationXml(PresetDictionaries.UseKey2005SPC, PresetDictionaries.Claims2005SPC);
            // 初始化RAC XML（区分Win/Office）
            var racClaims = isWindowsProduct ? PresetDictionaries.Claims2005WinRAC : PresetDictionaries.Claims2005OfficeRAC;
            var racUseKey = isWindowsProduct ? PresetDictionaries.UseKey2005WinRAC : PresetDictionaries.UseKey2005OfficeRAC;
            racXml = CreateRacActivationXml(racUseKey, racClaims);
            // 初始化PKC XML（更新产品密钥和配置ID）
            var pkcClaims = new Dictionary<string, string>(PresetDictionaries.Claims2005PKC);
            pkcClaims["ProductKey"] = productKey;
            pkcClaims["ProductKeyActConfigId"] = configId;
            pkcClaims["Binding"] = Convert.ToBase64String(PresetDictionaries.HWID.Concat(PresetDictionaries.RandomBuffer).ToArray());
            pkcXml = CreatePkcActivationXml(PresetDictionaries.UseKey2005PKC, pkcClaims);
        }

        /// <summary>
        /// 初始化2009版本的请求XML（PA）
        /// </summary>
        private static void Init2009VersionXml(string productKey, string configId, ref string paXml)
        {
            var paClaims = new Dictionary<string, string>(PresetDictionaries.Claims2009Office);
            paClaims["ProductKey"] = productKey;
            paClaims["ProductKeyActConfigId"] = configId;
            paClaims["Binding"] = Convert.ToBase64String(PresetDictionaries.HWID.Concat(PresetDictionaries.RandomBuffer).ToArray());
            paXml = CreatePaActivationXml(PresetDictionaries.UseKey2009Office, paClaims);
        }

        /// <summary>
        /// 执行2005版本的激活请求，获取错误码
        /// 修复原代码入参冗余问题（eulUrl重复）
        /// </summary>
        /// <summary>
        /// 执行2005版本的激活请求，获取错误码
        /// 修复原代码入参冗余问题（eulUrl重复）
        /// 新增：Win7 Retail专属PublishLicense模板替换逻辑 + isWin7参数透传
        /// </summary>
        /// <summary>
        /// 执行2005版本激活请求（修复Win7 Retail PublishLicense模板）
        /// </summary>
        private static async Task<string> Execute2005VersionActivation(bool isWindowsProduct, string spcUrl, string spcSoap, string spcXml,
            string racUrl, string racSoap, string racXml, string pkcUrl, string pkcSoap, string pkcXml,
            string eulUrl, string eulSoap, string productDescription)
        {
            // 获取SPC/RAC/PKC证书
            var spcCert = await GetCertificateAsync(spcUrl, spcSoap, spcXml);
            var racCert = await GetCertificateAsync(racUrl, racSoap, racXml);
            var pkcCert = await GetCertificateAsync(pkcUrl, pkcSoap, pkcXml);

            // PKC返回错误码直接返回
            if (pkcCert.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                return pkcCert;
            }

            // 修复1：识别Win7 Retail版本
            bool isWin7Retail = isWindowsProduct
                && productDescription.IndexOf("Windows 7", StringComparison.OrdinalIgnoreCase) >= 0
                && productDescription.IndexOf("Retail", StringComparison.OrdinalIgnoreCase) >= 0;

            var eulClaims = isWindowsProduct ? PresetDictionaries.Claims2005WinEUL : PresetDictionaries.Claims2005OfficeEUL;
            Dictionary<string, string> eulUseKey;

            // 修复2：Win7 Retail使用专属PublishLicense模板（带占位符）
            if (isWin7Retail)
            {
                eulUseKey = new Dictionary<string, string>(PresetDictionaries.UseKey2005WinEUL);
                // 替换为Win7 Retail专属模板，{0}用于填入真实证书
                eulUseKey["PublishLicense"] = PresetDictionaries.GetLargeXml("Win7RetailPublishLicense");
            }
            else
            {
                eulUseKey = isWindowsProduct ? PresetDictionaries.UseKey2005WinEUL : PresetDictionaries.UseKey2005OfficeEUL;
            }

            // 修复3：传入isWin7参数，让XML生成适配Win7规则
            var eulRequestXml = CreateEulActivationXml(spcCert, racCert, pkcCert, eulUseKey, eulClaims, isWin7Retail);

            // 获取EUL激活错误码
            return await GetActivationErrorCodeAsync(eulUrl, eulSoap, eulRequestXml, true);
        }
        /// <summary>
        /// 执行2009版本的激活请求，获取错误码
        /// </summary>
        private static async Task<string> Execute2009VersionActivation(string productDesc, string productKey, string configId, string paUrl, string paSoap, string paXml)
        {
            // 首次PA请求
            var paErrorCode = await GetActivationErrorCodeAsync(paUrl, paSoap, paXml);

            // Win10 RTM特殊处理：重新请求PA（原代码逻辑保留）
            if (paErrorCode == ErrorCode.OnlineKey && productDesc.IndexOf("Win 10 RTM", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                var paClaims = new Dictionary<string, string>(PresetDictionaries.Claims2009Office);
                paClaims["ProductKey"] = productKey;
                paClaims["ProductKeyActConfigId"] = configId;
                paClaims["Binding"] = Convert.ToBase64String(PresetDictionaries.HWID1);
                paClaims["ClientSystemTime"] = GetLocalIsoTime();
                paClaims["ClientSystemTimeUtc"] = GetUtcIsoTime();

                var rePaXml = CreatePaActivationXml(PresetDictionaries.UseKey2009Office, paClaims);
                paErrorCode = await GetActivationErrorCodeAsync(paUrl, paSoap, rePaXml);
            }

            return paErrorCode;
        }
        #endregion
    }
}