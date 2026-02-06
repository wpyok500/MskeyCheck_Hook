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
using System.Xml;

// .NET 4.8 需添加程序集引用：
// System.Net.Http、System.Web、System.Xml、System.Core、System.Configuration
namespace CreateActXml
{
    /// <summary>
    /// 微软产品密钥激活结果查询API（获取HResult错误码）
    /// 支持2005/2009版本，Win/Office产品激活校验
    /// .NET Framework 4.8 重构版（仅保留2009核心逻辑）
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
            public const string ProductActivation = "ProductActivation";
        }
        /// <summary>
        /// 错误码常量
        /// </summary>
        private static class ErrorCode
        {
            public const string Unknown = "Unknown";
            public const string OnlineKey = "Online Key";
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
        /// 版本化激活配置（仅保留2009）
        /// </summary>
        private class VersionedActivationConfig
        {
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
        /// 预置声明/密钥字典（仅保留2009相关）
        /// </summary>
        private static class PresetDictionaries
        {
            // HWID相关
            public static readonly byte[] HWID = { 42, 0, 0, 0, 1, 0, 2, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0 };
            public static readonly byte[] HWID1 = { 42, 0, 0, 0, 1, 0, 2, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 150, 43, 54, 158, 200, 66, 82, 200, 158, 214, 126, 148, 36, 29, 251, 53, 252, 37 };
            public static readonly byte[] RandomBuffer = new byte[18];

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
            /// 封装大段XML证书内容（仅保留Office2009相关）
            /// </summary>
            public static string GetLargeXml(string xmlKey)
            {
                switch (xmlKey)
                {
                    // 核心保留：Office2009PublishLicense完整内容
                    case "Office2009PublishLicense":
                        return @"<?xml version=""1.0"" encoding=""utf-8""?><rg:licenseGroup xmlns:rg=""urn:mpeg:mpeg21:2003:01-REL-R-NS""><r:license xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS"" licenseId=""{7c6134e6-409c-47ed-a9b5-514c983557a0}"" xmlns:sx=""urn:mpeg:mpeg21:2003:01-REL-SX-NS"" xmlns:mx=""urn:mpeg:mpeg21:2003:01-REL-MX-NS"" xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2"" xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""><r:title>Office 16 Publishing License (Public)</r:title><r:grant><r:forAll varName=""productId""><r:anXmlExpression>/sl:productId/sl:pid</r:anXmlExpression></r:forAll><r:forAll varName=""binding""></r:forAll><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>uzDfZ3WsHY4/UKthrglDqsLw4BqrlOWlNdLBnLD/5sdAUXnv+2kB9jJJPK2TYkbkQ5bfK4QfS8h050WPtpN/NGL7batTKnEjNnRNrenM8+YAT9Ne7K7xCwgJdb08rOZyMqQPKtPr1p6FCwPY7zBvOmtNdvVs0psxwEuq2DmFz1g8+WJw9zGgqI4qkYA7P/yaN0lbQpvH3p1v68DogX7BLd6Z+Z+3MNG1Lh+k11kmd+lM8RaLq74zT8OSZDJ9McD9i/4JaB0kJfdV5oGb0ZbWvW/3Z8pQVf7tA5s3J1Tpp3/nrvV5WtZMZ3nGemTFRP5dxbH5y4YSBoKFGOYCyQH3pQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><r:issue/><r:grant><r:forAll varName=""application""><r:anXmlExpression>editionId[@value="""" or @value=""Office16ProPlusMSDNR_Retail""]</r:anXmlExpression></r:forAll><r:forAll varName=""appid""><r:propertyPossessor><tm:application varRef=""application""/><r:trustedRootIssuers><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>lAi6wXhcWOjn1rN1aIy6z4YBcYlkdrxP9EEw7iiD0tg6i0aVOgZ/FS6IxiOgZXYwTgK/BHA7QN6/lvxnecZ2cETT7w7ZRByGUN1zTQKFwXdyQz/xdp5kZ81bmI3EQWLJBT6iW5K8HZr0qRsQRlExUrWZSOI449+Br2QgOMcBMS3FEMBS8XCBPgZ3z/V9ydztWjhopBB0ZngebWEjqwtlrXEB1M+WOPWUcljdJlp5pXNkiqCrJEzenMJ+tfTfD/8zv08LdhhIAmx1VLViItRqO9OD7l313X7bVyfTWTxGmf7D9YS5Sa0UCiOXM0qVZCVuQ5CzjLRLa13FaJurQ6SBhQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder></r:trustedRootIssuers></r:propertyPossessor></r:forAll><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>ptV5l33YkYwdOV/Ru16t2VcbVg92rhNO1ng3kIn/AY/c/HlfUuVxwR4F4F3JoxbDQ4wiNf1QwQaAJdl/1pHy0iY3Hb60KLMuqOb4/C2EsICU2cOuhVxgVIoM+aqEkkFHyUx1E6+TbCSAvv0PQR7ns6h9CLlXPHZ6w6P8s0L/rAs=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><sl:runSoftware/><sl:appId varRef=""appid""/><r:allConditions><r:allConditions><sl:productPolicies xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2""><sl:priority>400</sl:priority><sl:policyStr name=""Security-SPP-Reserved-ProductUniquenessGroupID"">05DC53C7-C5BE-4D6B-9A3E-1984B2E7F47C</sl:policyStr><sl:policyStr name=""Security-SPP-Reserved-Family"" attributes=""override-only"">Office16ProPlusMSDNR_Retail</sl:policyStr></sl:productPolicies><sl:proxyExecutionKey xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2""></sl:proxyExecutionKey></r:allConditions><mx:renderer><sl:binding varRef=""binding""/><sl:productId varRef=""productId""/></mx:renderer></r:allConditions></r:grant><r:allConditions><sl:businessRules xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2""></sl:businessRules></r:allConditions></r:grant><r:issuer><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.microsoft.com/xrml/lwc14n""/><SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1""/><Reference><Transforms><Transform Algorithm=""urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform""/><Transform Algorithm=""http://www.microsoft.com/xrml/lwc14n""/></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""/><DigestValue>TtnlPLgMGSKY+gXlVPTp9bLmY9U=</DigestValue></Reference></SignedInfo><SignatureValue>DcPeLWssKlnrpLhnt5r+v1SSSzTvaiLPMk9DZHsKFcq7wD7umhzIw6+BnasQK20EvfZkXbQtzskBjRsZ+DXxUgp4F/CGTk7bWRDN//XQOHOP1BPyVhNVylcqjQw3K7ZKVtsbWDpzOskp9Rc28mh/XUhKyMyueFpFeKGhC7pbwMi0pk0JcFEyCwbiCYTYx9bCSipKx1JI5DpSfCZdql6X7JOsdiTjQYVvcLzkstwWmc2OCZgZexMdPB7Td5f3YR6kHfFOXP9Q7EIxsCXgDMw1L1VpJwOtXnCX/qntd9Z2XvilFv6CtJetndKafZEBzyz+997l6Iv9pL5cqs62TwhSPw==</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>lAi6wXhcWOjn1rN1aIy6z4YBcYlkdrxP9EEw7iiD0tg6i0aVOgZ/FS6IxiOgZXYwTgK/BHA7QN6/lvxnecZ2cETT7w7ZRByGUN1zTQKFwXdyQz/xdp5kZ81bmI3EQWLJBT6iW5K8HZr0qRsQRlExUrWZSOI449+Br2QgOMcBMS3FEMBS8XCBPgZ3z/V9ydztWjhopBB0ZngebWEjqwtlrXEB1M+WOPWUcljdJlp5pXNkiqCrJEzenMJ+tfTfD/8zv08LdhhIAmx1VLViItRqO9OD7l313X7bVyfTWTxGmf7D9YS5Sa0UCiOXM0qVZCVuQ5CzjLRLa13FaJurQ6SBhQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature><r:details><r:timeOfIssue>2018-06-27T23:08:05Z</r:timeOfIssue></r:details></r:issuer><r:otherInfo xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS""><tm:infoTables xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""><tm:infoList tag=""#global""><tm:infoStr name=""licenseType"">msft:sl/PL/GENERIC/PUBLIC</tm:infoStr><tm:infoStr name=""licenseVersion"">2.0</tm:infoStr><tm:infoStr name=""licensorUrl"">https://licensing.microsoft.com</tm:infoStr><tm:infoStr name=""licenseCategory"">msft:sl/PL/GENERIC/PUBLIC</tm:infoStr><tm:infoStr name=""productSkuId"">{84832881-46EF-4124-8ABC-EB493CDCF78E}</tm:infoStr><tm:infoStr name=""privateCertificateId"">{997cb5ed-bf97-40c8-857a-19945436aa99}</tm:infoStr><tm:infoStr name=""applicationId"">{0ff1ce15-a989-479d-af46-f275c6370663}</tm:infoStr><tm:infoStr name=""productName"">Office 16, Office16ProPlusMSDNR_Retail edition</tm:infoStr><tm:infoStr name=""Family"">Office16ProPlusMSDNR_Retail</tm:infoStr><tm:infoStr name=""productAuthor"">Microsoft Corporation</tm:infoStr><tm:infoStr name=""productDescription"">Office 16</tm:infoStr><tm:infoStr name=""clientIssuanceCertificateId"">{CE939C0E-53F7-4011-A286-78B6975FA5F0}</tm:infoStr><tm:infoStr name=""hwid:ootGrace"">3</tm:infoStr><tm:infoStr name=""migratable"">true</tm:infoStr><tm:infoStr name=""referralData"">ReferralId=000000;PartnerId=00000000-0000-0000-0000-000000000000</tm:infoStr></tm:infoList></tm:infoTables></r:otherInfo></r:license><r:license xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS"" licenseId=""{997cb5ed-bf97-40c8-857a-19945436aa99}"" xmlns:sx=""urn:mpeg:mpeg21:2003:01-REL-SX-NS"" xmlns:mx=""urn:mpeg:mpeg21:2003:01-REL-MX-NS"" xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2"" xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""><r:title>Office 16 Publishing License (Private)</r:title><r:grant><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>uzDfZ3WsHY4/UKthrglDqsLw4BqrlOWlNdLBnLD/5sdAUXnv+2kB9jJJPK2TYkbkQ5bfK4QfS8h050WPtpN/NGL7batTKnEjNnRNrenM8+YAT9Ne7K7xCwgJdb08rOZyMqQPKtPr1p6FCwPY7zBvOmtNdvVs0psxwEuq2DmFz1g8+WJw9zGgqI4qkYA7P/yaN0lbQpvH3p1v68DogX7BLd6Z+Z+3MNG1Lh+k11kmd+lM8RaLq74zT8OSZDJ9McD9i/4JaB0kJfdV5oGb0ZbWvW/3Z8pQVf7tA5s3J1Tpp3/nrvV5WtZMZ3nGemTFRP5dxbH5y4YSBoKFGOYCyQH3pQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><r:issue/><r:grant><r:forAll varName=""anyRight""></r:forAll><r:forAll varName=""appid""></r:forAll><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>ptV5l33YkYwdOV/Ru16t2VcbVg92rhNO1ng3kIn/AY/c/HlfUuVxwR4F4F3JoxbDQ4wiNf1QwQaAJdl/1pHy0iY3Hb60KLMuqOb4/C2EsICU2cOuhVxgVIoM+aqEkkFHyUx1E6+TbCSAvv0PQR7ns6h9CLlXPHZ6w6P8s0L/rAs=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><tm:decryptContent/><tm:symmetricKey><tm:AESKeyValue size=""16"">AAAAAAAAAAAAAAAAAAAAAA==</tm:AESKeyValue></tm:symmetricKey><r:prerequisiteRight><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>ptV5l33YkYwdOV/Ru16t2VcbVg92rhNO1ng3kIn/AY/c/HlfUuVxwR4F4F3JoxbDQ4wiNf1QwQaAJdl/1pHy0iY3Hb60KLMuqOb4/C2EsICU2cOuhVxgVIoM+aqEkkFHyUx1E6+TbCSAvv0PQR7ns6h9CLlXPHZ6w6P8s0L/rAs=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><r:right varRef=""anyRight""/><sl:appId varRef=""appid""/><r:trustedRootIssuers><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>uzDfZ3WsHY4/UKthrglDqsLw4BqrlOWlNdLBnLD/5sdAUXnv+2kB9jJJPK2TYkbkQ5bfK4QfS8h050WPtpN/NGL7batTKnEjNnRNrenM8+YAT9Ne7K7xCwgJdb08rOZyMqQPKtPr1p6FCwPY7zBvOmtNdvVs0psxwEuq2DmFz1g8+WJw9zGgqI4qkYA7P/yaN0lbQpvH3p1v68DogX7BLd6Z+Z+3MNG1Lh+k11kmd+lM8RaLq74zT8OSZDJ9McD9i/4JaB0kJfdV5oGb0ZbWvW/3Z8pQVf7tA5s3J1Tpp3/nrvV5WtZMZ3nGemTFRP5dxbH5y4YSBoKFGOYCyQH3pQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder></r:trustedRootIssuers></r:prerequisiteRight></r:grant></r:grant><r:issuer><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.microsoft.com/xrml/lwc14n""/><SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1""/><Reference><Transforms><Transform Algorithm=""urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform""/><Transform Algorithm=""http://www.microsoft.com/xrml/lwc14n""/></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""/><DigestValue>3bFwQHj4OtR0bjG1eiTQfZ0jFWQ=</DigestValue></Reference></SignedInfo><SignatureValue>NbYcpkEFJ1okOjpLKKktLnJsQ7lI3HG052adOCdhPf0qBxgXFTW25k+NFwp1UELR3ls2R57/3QJsSu1fjxjarpHVud4i22jou5+bMrDok5J0V6oPFaYBJce6Mjw8xcpBOZczqMfUhAa/PeYvJSG8wAi/2Wthco6Gt5dwVxFEQc7Zpr7pH3OxZz4ujKH/4WcgyjjlrwvW8IQ2Xfbcl562K449G1VOmB2G1XwfdSFCliJiO2FV44Ztk0gPkBNHcjrC08TipMTGbqJH8tQn4VJ5zueoMoxCCLMPQ/kVW4wjS5VGfWTEIzvvy2OSdY3tdnt4b3dbMBMVRixXVn0Cp2kh1Q==</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>lAi6wXhcWOjn1rN1aIy6z4YBcYlkdrxP9EEw7iiD0tg6i0aVOgZ/FS6IxiOgZXYwTgK/BHA7QN6/lvxnecZ2cETT7w7ZRByGUN1zTQKFwXdyQz/xdp5kZ81bmI3EQWLJBT6iW5K8HZr0qRsQRlExUrWZSOI449+Br2QgOMcBMS3FEMBS8XCBPgZ3z/V9ydztWjhopBB0ZngebWEjqwtlrXEB1M+WOPWUcljdJlp5pXNkiqCrJEzenMJ+tfTfD/8zv08LdhhIAmx1VLViItRqO9OD7l313X7bVyfTWTxGmf7D9YS5Sa0UCiOXM0qVZCVuQ5CzjLRLa13FaJurQ6SBhQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature><r:details><r:timeOfIssue>2018-06-27T23:08:05Z</r:timeOfIssue></r:details></r:issuer><r:otherInfo xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS""><tm:infoTables xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""><tm:infoList tag=""#global""><tm:infoStr name=""licenseType"">msft:sl/PL/GENERIC/PRIVATE</tm:infoStr><tm:infoStr name=""licenseVersion"">2.0</tm:infoStr><tm:infoStr name=""licensorUrl"">https://licensing.microsoft.com</tm:infoStr><tm:infoStr name=""licenseCategory"">msft:sl/PL/GENERIC/PRIVATE</tm:infoStr><tm:infoStr name=""publicCertificateId"">{7c6134e6-409c-47ed-a9b5-514c983557a0}</tm:infoStr><tm:infoStr name=""clientIssuanceCertificateId"">{CE939C0E-53F7-4011-A286-78B6975FA5F0}</tm:infoStr><tm:infoStr name=""hwid:ootGrace"">3</tm:infoStr><tm:infoStr name=""migratable"">true</tm:infoStr></tm:infoList></tm:infoTables></r:otherInfo></r:license></rg:licenseGroup>";
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
        /// 构建SOAP信封XML（核心XML生成逻辑）
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

        /// <summary>
        /// 写入UseKey/Claims子节点
        /// </summary>
        /// <param name="xmlWriter">XML写入器</param>
        /// <param name="parentNodeName">父节点名称（UseKey/Claims）</param>
        /// <param name="dataDict">节点数据字典</param>
        /// <param name="isClaims">是否为Claims节点</param>
        /// <param name="isWin7">是否为Win7系统</param>
        private static void WriteKeyOrClaimsNode(XmlTextWriter xmlWriter, string parentNodeName, Dictionary<string, string> dataDict, bool isClaims = false, bool isWin7 = false)
        {
            if (xmlWriter == null)
                throw new ArgumentNullException(nameof(xmlWriter));
            if (string.IsNullOrEmpty(parentNodeName))
                throw new ArgumentNullException(nameof(parentNodeName));

            try
            {
                // 1. 写入 <UseKey> 或 <Claims>
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
                            xmlWriter.WriteString(kvp.Value ?? string.Empty);
                        }
                        else
                        {
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
        /// .NET 4.8 适配：添加TLS1.2强制配置
        /// </summary>
        private static HttpClient CreateHttpClient()
        {
            // .NET 4.8 强制启用TLS1.2/1.1，解决微软激活服务器HTTPS连接失败
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
            ServicePointManager.DefaultConnectionLimit = 512;
            ServicePointManager.Expect100Continue = false;
            ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;

            var handler = new HttpClientHandler { AllowAutoRedirect = false };
            var client = new HttpClient(handler);

            // 统一请求头配置
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("text/*"));
            client.DefaultRequestHeaders.ConnectionClose = false;
            client.DefaultRequestHeaders.UserAgent.ParseAdd(DefaultUserAgent);
            client.Timeout = TimeSpan.FromSeconds(30);

            return client;
        }

        /// <summary>
        /// 解析XML响应，提取目标值（HResult/证书/错误码）
        /// </summary>
        /// <param name="xmlContent">XML响应内容</param>
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
                        if (nameValue == "EndUserLicense")
                        {
                            return ErrorCode.OnlineKey;
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

        #region 激活XML创建方法（仅保留2009版本PA）
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
        /// 异步POST请求获取激活错误码
        /// </summary>
        /// <param name="url">请求地址</param>
        /// <param name="soapAction">SOAPAction头</param>
        /// <param name="requestXml">请求XML</param>
        /// <returns>错误码</returns>
        private static async Task<string> GetActivationErrorCodeAsync(string url, string soapAction, string requestXml, bool is2005Eul = false)
        {
            try
            {
                using (var client = CreateHttpClient())
                {
                    // 强制指定UTF-8编码，解决乱码
                    using (var content = new StringContent(requestXml, Utf8NoBom, ContentTypeXml))
                    {
                        content.Headers.ContentType.CharSet = "utf-8";

                        // 清空原有请求头，避免冲突
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
                                // .NET 4.8适配StreamReader读取错误响应
                                using (var stream = await response.Content.ReadAsStreamAsync())
                                using (var sr = new StreamReader(stream, Utf8NoBom))
                                {
                                    responseContent = await sr.ReadToEndAsync();
                                }
                            }

                            // 解码HTML/URL转义，避免XML解析失败
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
        /// 同步POST请求获取激活错误码（基于异步封装）
        /// </summary>
        public static string GetActivationErrorCode(string url, string soapAction, string requestXml, bool is2005Eul = false)
        {
            return GetActivationErrorCodeAsync(url, soapAction, requestXml, is2005Eul).GetAwaiter().GetResult();
        }
        #endregion

        #region 核心业务方法（仅保留2009逻辑，增加2005版本判断）
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
                // 初始化随机缓冲区
                new Random().NextBytes(PresetDictionaries.RandomBuffer);
                // 更新时间戳为当前时间
                UpdatePresetClaimsTime();

                // 判断是否为2005版本（通过配置ID识别）
                var is2005Version = productKeyActConfigId.Contains("2005");

                // 初始化2009版本PA XML（核心逻辑）
                string paXml = null;
                var paClaims = new Dictionary<string, string>(PresetDictionaries.Claims2009Office);
                paClaims["ProductKey"] = productKey;
                paClaims["ProductKeyActConfigId"] = productKeyActConfigId;
                paClaims["Binding"] = Convert.ToBase64String(PresetDictionaries.HWID.Concat(PresetDictionaries.RandomBuffer).ToArray());

                // 关键修改：如果是2005版本，修改ProductKeyType为2005格式
                if (is2005Version)
                {
                    paClaims["ProductKeyType"] = "msft:rm/algorithm/pkey/2005";
                }

                paXml = CreatePaActivationXml(PresetDictionaries.UseKey2009Office, paClaims);

                // 2009版本服务配置
                var paUrl = VersionedActivationConfig.Office2009PA.Url;
                var paSoap = VersionedActivationConfig.Office2009PA.SoapAction;

                // 执行激活请求，获取错误码
                var paErrorCode = await GetActivationErrorCodeAsync(paUrl, paSoap, paXml);

                // Win10 RTM特殊处理（保留原有逻辑）
                if (paErrorCode == ErrorCode.OnlineKey && productDescription.IndexOf("Win 10 RTM", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    var rePaClaims = new Dictionary<string, string>(PresetDictionaries.Claims2009Office);
                    rePaClaims["ProductKey"] = productKey;
                    rePaClaims["ProductKeyActConfigId"] = productKeyActConfigId;
                    rePaClaims["Binding"] = Convert.ToBase64String(PresetDictionaries.HWID1);
                    rePaClaims["ClientSystemTime"] = GetLocalIsoTime();
                    rePaClaims["ClientSystemTimeUtc"] = GetUtcIsoTime();

                    // 同样处理2005版本的ProductKeyType
                    if (is2005Version)
                    {
                        rePaClaims["ProductKeyType"] = "msft:rm/algorithm/pkey/2005";
                    }

                    var rePaXml = CreatePaActivationXml(PresetDictionaries.UseKey2009Office, rePaClaims);
                    paErrorCode = await GetActivationErrorCodeAsync(paUrl, paSoap, rePaXml);
                }

                // 确保错误码非空
                return string.IsNullOrWhiteSpace(paErrorCode) ? ErrorCode.Unknown : paErrorCode;
            }
            catch (Exception ex)
            {
                Trace.WriteLine(string.Format("[ActivationApi] 核心激活逻辑异常：{0} {1}", ex.Message, ex.StackTrace));
                return ErrorCode.Unknown;
            }
        }

        /// <summary>
        /// 同步获取产品密钥激活的HResult错误码（基于异步封装）
        /// </summary>
        public static string GetActivationHResult(string productKey, string productDescription, string productKeyActConfigId)
        {
            return GetActivationHResultAsync(productKey, productDescription, productKeyActConfigId).GetAwaiter().GetResult();
        }
        #endregion

        #region 内部辅助方法
        /// <summary>
        /// 更新预置声明中的时间戳为当前时间
        /// </summary>
        private static void UpdatePresetClaimsTime()
        {
            var localTime = GetLocalIsoTime();
            var utcTime = GetUtcIsoTime();

            PresetDictionaries.Claims2009Office["ClientSystemTime"] = localTime;
            PresetDictionaries.Claims2009Office["ClientSystemTimeUtc"] = utcTime;
        }
        #endregion
    }
}