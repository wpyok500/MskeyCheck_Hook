using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace MsKeyChecker
{
    /// <summary>
    /// 适配.NET 4.8的产品密钥验证/激活核心类
    /// </summary>
    public class KeyChecker : IDisposable
    {
        private readonly PKeyConfig _pkc;
        private readonly WebClient _webClient;
        private bool _disposed = false; // 标记是否已释放

        private const string PubLicense = @"<?xml version=""1.0"" encoding=""utf-8""?><rg:licenseGroup xmlns:rg=""urn:mpeg:mpeg21:2003:01-REL-R-NS""><r:license xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS"" licenseId=""{add96a1a-5ae7-425d-935d-3b6effd43a92}"" xmlns:sx=""urn:mpeg:mpeg21:2003:01-REL-SX-NS"" xmlns:mx=""urn:mpeg:mpeg21:2003:01-REL-MX-NS"" xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2"" xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""><r:title>Windows(R) Publishing License (Public)</r:title><r:grant><r:forAll varName=""productId""><r:anXmlExpression>/sl:productId/sl:pid</r:anXmlExpression></r:forAll><r:forAll varName=""binding""></r:forAll><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>v0JgOuEWuaA3INoAK10wY7PLaEhyfjfL5A2joNwBR/3ziJxewXKy5QDzZvD3C9eVdvlSqFCDpZEDUxVWvFFeYKI5YkTeK5x7X4nQPodwZAoTJklTUWpfZNslLYJVMaxRvs8htxKoIbvmssqN4Dhy3Oa7HT80GcOvS95M7UCvXcQ7TjrQUV9QNb0w6WLdMVpuktek1CVi4XQ3ELIHZJhyKAtWNGRN4kxZL9nYyDvZ8be5rlGTuhEsgi1oFqnjzMLYXU4wkF/W8mRedIkvoBu3kCjuwEqsr9P5sIbHowqFX5sRxmTrgwoCXPCtFyXCwu9hO75mvb1I1sCuv8W0gTfMtw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><r:issue/><r:grant><r:forAll varName=""application""><r:anXmlExpression>editionId[@value="""" or @value=""EnterpriseS""]</r:anXmlExpression></r:forAll><r:forAll varName=""appid""><r:propertyPossessor><tm:application varRef=""application""/><r:trustedRootIssuers><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>tajcnLtdaeK0abuL2BpVC7obdfSChnHAx7TSn/37DwbTDegkDkEnbr0YyO/Q5Jluj5QD897+nWW54RDbYYTdNgWjyUpwYEJFXSZtd8LFK2mbIjKfG2HIShp6JJARlrgObR89a1EH716nP3PbJk6PWQa6VfjBzPQUgSVywIRU+OKbnzNbUVmQ/rAN6+AN/8fRmFhyKqOAiV/Np2jBtGNxLXm9ebMdm5cB8/YNrjp5Ey0nyAtYvovb0B7wnQZfolMF+OFiqzWJo2Ze0O7WHsWBHtIlGR3+c/IjxUJAsI7O3U4hncCZdvlC5GORI2YL9YHZgU9guSPLhAybQ3IGg7LBuQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder></r:trustedRootIssuers></r:propertyPossessor></r:forAll><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>17FgQIuX2S7YIVn8PIeN+qANo4/TUbV8CH5TzbXwmWo4WVI4npVqI4NNhRVsP0ICgMpql1jgAm75dZDBPTzRTCj+Ni0DXIvk6Whlo/ClK/fpZUO3ORQ9VmBE3cXeQQAehgVlUUIzOmG4EeP1i91PCGf5O7I4ayYS2FeQUj+6hyk=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><sl:runSoftware/><sl:appId varRef=""appid""/><r:allConditions><r:allConditions><sl:productPolicies xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2""><sl:priority>500</sl:priority><sl:policyInt name=""Security-SPP-Reserved-Store-Token-Required"" attributes=""override-only"">0</sl:policyInt><sl:policyInt name=""Kernel-NonGenuineNotificationType"" attributes=""override-only"">2</sl:policyInt><sl:policyStr name=""Security-SPP-Reserved-Windows-Version-V2"" attributes=""override-only"">10.0</sl:policyStr><sl:policyInt name=""Security-SPP-WriteWauMarker"">1</sl:policyInt><sl:policyStr name=""Security-SPP-Reserved-Family"" attributes=""override-only"">EnterpriseS</sl:policyStr></sl:productPolicies><sl:proxyExecutionKey xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2""></sl:proxyExecutionKey><sl:externalValidator xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2""><sl:type>msft:sl/externalValidator/generic</sl:type><sl:data Algorithm=""msft:rm/algorithm/flags/1.0"">DAAAAAEAAAAFAAAA</sl:data></sl:externalValidator></r:allConditions><mx:renderer><sl:binding varRef=""binding""/><sl:productId varRef=""productId""/></mx:renderer></r:allConditions></r:grant><r:allConditions><sl:businessRules xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2""></sl:businessRules></r:allConditions></r:grant><r:issuer><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.microsoft.com/xrml/lwc14n""/><SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1""/><Reference><Transforms><Transform Algorithm=""urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform""/><Transform Algorithm=""http://www.microsoft.com/xrml/lwc14n""/></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""/><DigestValue>ivMENCvkqJvb41ZNgue9GpfjWDI=</DigestValue></Reference></SignedInfo><SignatureValue>exwwz6jLpaJ0u1KEEDOCFDXwUAEwI8jUpcamyUkFyqbuYBVCinoihNCtgZAvXcQ+N35MNSXLKXlXpttYE0M2O8dZWR/Frxt38RWxCQj/4heGIwPqQJ7KUZtOdBvytjA6XSvv6uqq1aNAaSWyb7l7jkXc14ycfvxILMVqYdmkIw6BQNZ8/R/anl4VQjAeBdg/+DrcxoHvVT1pVe5PJkrPFRi2B7+0P0oWBljataVjwqDnxYfcJq7lkErHsl78sH2rWPOP/carliYgFNTyEc8437MN5xkNJmeQpsAyTpfE+H7r74WXsk59aU7NoUxteOBRzUNZCgCp2Trr09awd5k2Pg==</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>tajcnLtdaeK0abuL2BpVC7obdfSChnHAx7TSn/37DwbTDegkDkEnbr0YyO/Q5Jluj5QD897+nWW54RDbYYTdNgWjyUpwYEJFXSZtd8LFK2mbIjKfG2HIShp6JJARlrgObR89a1EH716nP3PbJk6PWQa6VfjBzPQUgSVywIRU+OKbnzNbUVmQ/rAN6+AN/8fRmFhyKqOAiV/Np2jBtGNxLXm9ebMdm5cB8/YNrjp5Ey0nyAtYvovb0B7wnQZfolMF+OFiqzWJo2Ze0O7WHsWBHtIlGR3+c/IjxUJAsI7O3U4hncCZdvlC5GORI2YL9YHZgU9guSPLhAybQ3IGg7LBuQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature><r:details><r:timeOfIssue>2016-01-01T00:00:00Z</r:timeOfIssue></r:details></r:issuer><r:otherInfo xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS""><tm:infoTables xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""><tm:infoList tag=""#global""><tm:infoStr name=""licenseType"">msft:sl/PL/GENERIC/PUBLIC</tm:infoStr><tm:infoStr name=""licenseVersion"">2.0</tm:infoStr><tm:infoStr name=""licensorUrl"">http://licensing.microsoft.com</tm:infoStr><tm:infoStr name=""licenseCategory"">msft:sl/PL/GENERIC/PUBLIC</tm:infoStr><tm:infoStr name=""productSkuId"">{cce9d2de-98ee-4ce2-8113-222620c64a27}</tm:infoStr><tm:infoStr name=""privateCertificateId"">{38c2c1c2-f73e-4fb2-bb44-d8a52fdcbc51}</tm:infoStr><tm:infoStr name=""applicationId"">{55c92734-d682-4d71-983e-d6ec3f16059f}</tm:infoStr><tm:infoStr name=""productName"">Windows(R), EnterpriseS edition</tm:infoStr><tm:infoStr name=""Family"">EnterpriseS</tm:infoStr><tm:infoStr name=""productAuthor"">Microsoft Corporation</tm:infoStr><tm:infoStr name=""productDescription"">Windows(R) Operating System</tm:infoStr><tm:infoStr name=""clientIssuanceCertificateId"">{4961cc30-d690-43be-910c-8e2db01fc5ad}</tm:infoStr><tm:infoStr name=""hwid:ootGrace"">0</tm:infoStr></tm:infoList></tm:infoTables></r:otherInfo></r:license><r:license xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS"" licenseId=""{38c2c1c2-f73e-4fb2-bb44-d8a52fdcbc51}"" xmlns:sx=""urn:mpeg:mpeg21:2003:01-REL-SX-NS"" xmlns:mx=""urn:mpeg:mpeg21:2003:01-REL-MX-NS"" xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2"" xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""><r:title>Windows(R) Publishing License (Private)</r:title><r:grant><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>v0JgOuEWuaA3INoAK10wY7PLaEhyfjfL5A2joNwBR/3ziJxewXKy5QDzZvD3C9eVdvlSqFCDpZEDUxVWvFFeYKI5YkTeK5x7X4nQPodwZAoTJklTUWpfZNslLYJVMaxRvs8htxKoIbvmssqN4Dhy3Oa7HT80GcOvS95M7UCvXcQ7TjrQUV9QNb0w6WLdMVpuktek1CVi4XQ3ELIHZJhyKAtWNGRN4kxZL9nYyDvZ8be5rlGTuhEsgi1oFqnjzMLYXU4wkF/W8mRedIkvoBu3kCjuwEqsr9P5sIbHowqFX5sRxmTrgwoCXPCtFyXCwu9hO75mvb1I1sCuv8W0gTfMtw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><r:issue/><r:grant><r:forAll varName=""anyRight""></r:forAll><r:forAll varName=""appid""></r:forAll><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>17FgQIuX2S7YIVn8PIeN+qANo4/TUbV8CH5TzbXwmWo4WVI4npVqI4NNhRVsP0ICgMpql1jgAm75dZDBPTzRTCj+Ni0DXIvk6Whlo/ClK/fpZUO3ORQ9VmBE3cXeQQAehgVlUUIzOmG4EeP1i91PCGf5O7I4ayYS2FeQUj+6hyk=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><tm:decryptContent/><tm:symmetricKey><tm:AESKeyValue size=""16"">AAAAAAAAAAAAAAAAAAAAAA==</tm:AESKeyValue></tm:symmetricKey><r:prerequisiteRight><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>17FgQIuX2S7YIVn8PIeN+qANo4/TUbV8CH5TzbXwmWo4WVI4npVqI4NNhRVsP0ICgMpql1jgAm75dZDBPTzRTCj+Ni0DXIvk6Whlo/ClK/fpZUO3ORQ9VmBE3cXeQQAehgVlUUIzOmG4EeP1i91PCGf5O7I4ayYS2FeQUj+6hyk=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><r:right varRef=""anyRight""/><sl:appId varRef=""appid""/><r:trustedRootIssuers><r:keyHolder><r:info><KeyValue xmlns=""http://www.w3.org/2000/09/xmldsig#""><RSAKeyValue><Modulus>v0JgOuEWuaA3INoAK10wY7PLaEhyfjfL5A2joNwBR/3ziJxewXKy5QDzZvD3C9eVdvlSqFCDpZEDUxVWvFFeYKI5YkTeK5x7X4nQPodwZAoTJklTUWpfZNslLYJVMaxRvs8htxKoIbvmssqN4Dhy3Oa7HT80GcOvS95M7UCvXcQ7TjrQUV9QNb0w6WLdMVpuktek1CVi4XQ3ELIHZJhyKAtWNGRN4kxZL9nYyDvZ8be5rlGTuhEsgi1oFqnjzMLYXU4wkF/W8mRedIkvoBu3kCjuwEqsr9P5sIbHowqFX5sRxmTrgwoCXPCtFyXCwu9hO75mvb1I1sCuv8W0gTfMtw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder></r:trustedRootIssuers></r:prerequisiteRight></r:grant></r:grant><r:issuer><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.microsoft.com/xrml/lwc14n""/><SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1""/><Reference><Transforms><Transform Algorithm=""urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform""/><Transform Algorithm=""http://www.microsoft.com/xrml/lwc14n""/></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""/><DigestValue>hXPflMtQRYrmAY85A44Ewqbfedo=</DigestValue></Reference></SignedInfo><SignatureValue>qOP09nDXmVv1Ne9vEruoSNoV4mzBW371vp1E+uW8jTTC9BqESCaDyK38KhFsxyjz2UqKoelnaFDBTdbVN8VTzJIQCI5sSjMjWzBP31OUHOYDLUGQO7qpRDYwcGRQPsGsQwmNbyTPgq0m4wYcEU4FRj9LIi8B8saMo9xKAO4JNOB/lS8eScHcoUJAdAOoO4MZXfaqZmT90RrMPGPUIY3uTdjtiwL0B46bRdFNYwFuItdHdTUmXOPbXVWogPScSj3JYI9yhdcxjgyb9SxknG0UID9ogTI7HirsfuMvhWkyCSGtV1N4Rr9+c2oiDpWcYeaY4cWcTuSrb+S7vhA10jaJug==</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>tajcnLtdaeK0abuL2BpVC7obdfSChnHAx7TSn/37DwbTDegkDkEnbr0YyO/Q5Jluj5QD897+nWW54RDbYYTdNgWjyUpwYEJFXSZtd8LFK2mbIjKfG2HIShp6JJARlrgObR89a1EH716nP3PbJk6PWQa6VfjBzPQUgSVywIRU+OKbnzNbUVmQ/rAN6+AN/8fRmFhyKqOAiV/Np2jBtGNxLXm9ebMdm5cB8/YNrjp5Ey0nyAtYvovb0B7wnQZfolMF+OFiqzWJo2Ze0O7WHsWBHtIlGR3+c/IjxUJAsI7O3U4hncCZdvlC5GORI2YL9YHZgU9guSPLhAybQ3IGg7LBuQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature><r:details><r:timeOfIssue>2016-01-01T00:00:00Z</r:timeOfIssue></r:details></r:issuer><r:otherInfo xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS""><tm:infoTables xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""><tm:infoList tag=""#global""><tm:infoStr name=""licenseType"">msft:sl/PL/GENERIC/PRIVATE</tm:infoStr><tm:infoStr name=""licenseVersion"">2.0</tm:infoStr><tm:infoStr name=""licensorUrl"">http://licensing.microsoft.com</tm:infoStr><tm:infoStr name=""licenseCategory"">msft:sl/PL/GENERIC/PRIVATE</tm:infoStr><tm:infoStr name=""publicCertificateId"">{add96a1a-5ae7-425d-935d-3b6effd43a92}</tm:infoStr><tm:infoStr name=""clientIssuanceCertificateId"">{4961cc30-d690-43be-910c-8e2db01fc5ad}</tm:infoStr><tm:infoStr name=""hwid:ootGrace"">0</tm:infoStr><tm:infoStr name=""win:branding"">125</tm:infoStr></tm:infoList></tm:infoTables></r:otherInfo></r:license></rg:licenseGroup>";

        // SOAP模板
        private const string AtoReqTemplate = @"<?xml version=""1.0"" encoding=""utf-8""?>
<soap:Envelope
    xmlns:soapenc=""http://schemas.xmlsoap.org/soap/encoding/""
    xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/""
    xmlns:xsd=""http://www.w3.org/2001/XMLSchema""
    xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"">
    <soap:Body>
        <RequestSecurityToken
            xmlns=""http://schemas.xmlsoap.org/ws/2004/04/security/trust"">
            <TokenType>ProductActivation</TokenType>
            <RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</RequestType>
            <UseKey>
                <Values
                    xmlns:q1=""http://schemas.xmlsoap.org/ws/2004/04/security/trust"" soapenc:arrayType=""q1:TokenEntry[1]"">
                    <TokenEntry>
                        <Name>PublishLicense</Name>
                        <Value>{plxml}</Value>
                    </TokenEntry>
                </Values>
            </UseKey>
            <Claims>
                <Values
                    xmlns:q1=""http://schemas.xmlsoap.org/ws/2004/04/security/trust"" soapenc:arrayType=""q1:TokenEntry[14]"">
                    <TokenEntry>
                        <Name>BindingType</Name>
                        <Value>msft:rm/algorithm/hwid/4.0</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>Binding</Name>
                        <Value>{binding}</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>ProductKey</Name>
                        <Value>{pkey}</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>ProductKeyType</Name>
                        <Value>msft:rm/algorithm/pkey/2009</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>ProductKeyActConfigId</Name>
                        <Value>{act_config_id}</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>otherInfoPublic.licenseCategory</Name>
                        <Value>msft:sl/EUL/ACTIVATED/PUBLIC</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>otherInfoPrivate.licenseCategory</Name>
                        <Value>msft:sl/EUL/ACTIVATED/PRIVATE</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>otherInfoPublic.sysprepAction</Name>
                        <Value>rearm</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>otherInfoPrivate.sysprepAction</Name>
                        <Value>rearm</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>ClientInformation</Name>
                        <Value>SystemUILanguageId=1033;UserUILanguageId=1033;GeoId=244</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>ClientSystemTime</Name>
                        <Value>{systime}</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>ClientSystemTimeUtc</Name>
                        <Value>{utctime}</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>otherInfoPublic.secureStoreId</Name>
                        <Value>{secure_store_id}</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>otherInfoPrivate.secureStoreId</Name>
                        <Value>{secure_store_id}</Value>
                    </TokenEntry>
                </Values>
            </Claims>
        </RequestSecurityToken>
    </soap:Body>
</soap:Envelope>";

        private const string PkcReqTemplate = @"<?xml version=""1.0"" encoding=""utf-8""?>
<soap:Envelope
    xmlns:soapenc=""http://schemas.xmlsoap.org/soap/encoding/""
    xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/""
    xmlns:xsd=""http://www.w3.org/2001/XMLSchema""
    xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"">
    <soap:Body>
        <RequestSecurityToken
            xmlns=""http://schemas.xmlsoap.org/ws/2004/04/security/trust"">
            <TokenType>PKC</TokenType>
            <RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</RequestType>
            <UseKey>
                <Values xsi:nil=""1""/>
            </UseKey>
            <Claims>
                <Values
                    xmlns:q1=""http://schemas.xmlsoap.org/ws/2004/04/security/trust"" soapenc:arrayType=""q1:TokenEntry[3]"">
                    <TokenEntry>
                        <Name>ProductKey</Name>
                        <Value>{pkey}</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>ProductKeyType</Name>
                        <Value>msft:rm/algorithm/pkey/2009</Value>
                    </TokenEntry>
                    <TokenEntry>
                        <Name>ProductKeyActConfigId</Name>
                        <Value>{act_config_id}</Value>
                    </TokenEntry>
                </Values>
            </Claims>
        </RequestSecurityToken>
    </soap:Body>
</soap:Envelope>";

        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="pkc">PKeyConfig配置实例</param>
        public KeyChecker(PKeyConfig pkc)
        {
            _pkc = pkc;
            _webClient = new WebClient();

            // .NET 4.8 配置WebClient（忽略SSL验证）
            _webClient = new WebClient();
            _webClient.Headers.Add(HttpRequestHeader.Accept, "text/*");
            _webClient.Headers.Add(HttpRequestHeader.UserAgent, "SLSSoapClient");
            _webClient.Encoding = Encoding.UTF8;

            // 忽略SSL证书验证（核心：.NET 4.8 实现）
            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
        }

        #region 核心方法：验证/激活密钥
        /// <summary>
        /// 验证产品密钥（同步版，.NET 4.8 优先）
        /// </summary>
        /// <param name="pkey">产品密钥</param>
        /// <returns>验证结果</returns>
        public KeyResult QueryKey(string pkey)
        {
            if (!pkey.Contains("N"))
                return new KeyResult("N/A", "Product key is not PKEY2009.", false);

            try
            {
                var pkeyData = ProductKeyDecoder.Decode(pkey);
                var skuId = _pkc.GetConfigForGroup(pkeyData.Group).ConfigId.Trim('{', '}');
                var actData = Utils.EncodeKeyData(pkeyData.Group, pkeyData.Serial, pkeyData.Security, pkeyData.Upgrade);
                var actConfigId = Utils.XmlEscape($"msft2009:{skuId}&{actData}");

                // 渲染SOAP模板
                var payload = PkcReqTemplate
                    .Replace("{pkey}", pkey)
                    .Replace("{act_config_id}", actConfigId);

                // 发送请求（.NET 4.8 WebClient同步请求）
                _webClient.Headers.Remove(HttpRequestHeader.ContentType);
                _webClient.Headers.Remove("SOAPAction");
                _webClient.Headers.Add(HttpRequestHeader.ContentType, "text/xml; charset=utf-8");
                _webClient.Headers.Add("SOAPAction", "http://microsoft.com/SL/ProductCertificationService/IssueToken");

                string respXml;
                try
                {
                    respXml = _webClient.UploadString("https://activation.sls.microsoft.com/slpkc/SLCertifyProduct.asmx", payload);
                }
                catch (WebException ex)
                {
                    // 捕获Web异常（如网络错误、服务器返回错误）
                    using (var sr = new StreamReader(ex.Response.GetResponseStream()))
                    {
                        respXml = sr.ReadToEnd();
                    }
                    throw new Exception($"请求失败: {respXml}", ex);
                }

                // 解析响应
                return ParseSoapResponse(respXml);
            }
            catch (Exception ex)
            {
                return new KeyResult("N/A", $"Product key not compatible with provided pkeyconfig: {ex.Message}", false);
            }
        }

        /// <summary>
        /// 激活/消耗产品密钥（同步版）
        /// </summary>
        /// <param name="pkey">产品密钥</param>
        /// <param name="configExt">配置扩展（默认Retail）</param>
        /// <returns>激活结果</returns>
        public KeyResult ConsumeKey(string pkey, string configExt = "Retail")
        {
            if (!pkey.Contains("N"))
                return new KeyResult("N/A", "Product key is not PKEY2009.", false);

            try
            {
                var pkeyData = ProductKeyDecoder.Decode(pkey);
                var skuId = _pkc.GetConfigForGroup(pkeyData.Group).ConfigId.Trim('{', '}');
                var actData = Utils.EncodeKeyData(pkeyData.Group, pkeyData.Serial, pkeyData.Security, pkeyData.Upgrade);
                var actConfigId = Utils.XmlEscape($"msft2009:{skuId}&{actData}");

                // 构造请求参数
                var now = DateTime.Now;
                var timestamp = Utils.FormatTimestamp(now);
                var secureStoreId = Guid.NewGuid().ToString();
                var binding = Utils.GenerateBinding();
                var plXml = Utils.XmlEscape(PubLicense);

                // 渲染SOAP模板
                var payload = AtoReqTemplate
                    .Replace("{plxml}", plXml)
                    .Replace("{binding}", binding)
                    .Replace("{pkey}", pkey)
                    .Replace("{act_config_id}", actConfigId)
                    .Replace("{systime}", timestamp)
                    .Replace("{utctime}", timestamp)
                    .Replace("{secure_store_id}", secureStoreId);

                // 发送请求
                _webClient.Headers.Remove(HttpRequestHeader.ContentType);
                _webClient.Headers.Remove("SOAPAction");
                _webClient.Headers.Add(HttpRequestHeader.ContentType, "text/xml; charset=utf-8");
                _webClient.Headers.Add("SOAPAction", "http://microsoft.com/SL/ProductActivationService/IssueToken");

                string respXml;
                var url = $"https://activation.sls.microsoft.com/SLActivateProduct/SLActivateProduct.asmx?configextension={configExt}";
                try
                {
                    respXml = _webClient.UploadString(url, payload);
                }
                catch (WebException ex)
                {
                    using (var sr = new StreamReader(ex.Response.GetResponseStream()))
                    {
                        respXml = sr.ReadToEnd();
                    }
                    throw new Exception($"激活请求失败: {respXml}", ex);
                }

                // 解析响应
                return ParseSoapResponse(respXml);
            }
            catch (Exception ex)
            {
                return new KeyResult("N/A", $"Product key not compatible with provided pkeyconfig: {ex.Message}", false);
            }
        }

        /// <summary>
        /// 批量处理密钥（同步版）
        /// </summary>
        /// <param name="inputPath">输入文件路径（一行一个密钥）</param>
        /// <param name="outputPath">输出日志路径</param>
        /// <param name="isConsume">是否激活（true=激活，false=仅验证）</param>
        /// <returns>批量处理结果</returns>
        public BatchResult BatchProcess(string inputPath, string outputPath, bool isConsume)
        {
            var validKeys = new List<string>();
            var total = 0;

            // 校验文件是否存在
            if (!File.Exists(inputPath))
                throw new FileNotFoundException("输入文件不存在", inputPath);

            // 读取并处理
            using (var sw = new StreamWriter(outputPath, false, Encoding.UTF8))
            using (var sr = new StreamReader(inputPath, Encoding.UTF8))
            {
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    var pkey = line.Trim();
                    if (string.IsNullOrEmpty(pkey)) continue;
                    total++;

                    KeyResult result;
                    if (isConsume)
                        result = ConsumeKey(pkey);
                    else
                        result = QueryKey(pkey);

                    // 写入输出
                    sw.WriteLine($"Key: {pkey}");
                    sw.WriteLine(result.Success ? "Status: Online-valid" : "Status: Invalid");
                    if (!result.Success)
                    {
                        sw.WriteLine($"Error: {result.HResult}");
                        sw.WriteLine($"Message: {result.Message}");
                    }
                    sw.WriteLine();

                    if (result.Success)
                        validKeys.Add(pkey);
                }

                // 写入统计
                sw.WriteLine($"{validKeys.Count}/{total} keys are valid");
            }

            return new BatchResult(validKeys, total);
        }
        #endregion

        #region 辅助方法
        /// <summary>
        /// 解析SOAP响应（通用方法）
        /// </summary>
        /// <param name="xml">响应XML字符串</param>
        /// <returns>解析结果</returns>
        private KeyResult ParseSoapResponse(string xml)
        {
            try
            {
                var xDoc = XDocument.Parse(xml);
                var nsManager = new XmlNamespaceManager(new NameTable());
                nsManager.AddNamespace("soap", "http://schemas.xmlsoap.org/soap/envelope/");

                // 查找Fault节点
                var faultNode = xDoc.Descendants(XName.Get("Fault", "http://schemas.xmlsoap.org/soap/envelope/")).FirstOrDefault();
                if (faultNode == null)
                    return new KeyResult("0x0", "", true);

                // 解析错误信息
                var hresult = faultNode.Descendants("HRESULT").FirstOrDefault()?.Value ?? "N/A";
                var message = faultNode.Descendants("Message").FirstOrDefault()?.Value ?? "Unknown error";
                return new KeyResult(hresult, message, false);
            }
            catch (Exception ex)
            {
                return new KeyResult("N/A", $"解析响应失败: {ex.Message}", false);
            }
        }
        #endregion

        #region 资源释放
        
        // 实现IDisposable接口
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        /// <summary>
        /// 释放WebClient资源
        /// </summary>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                // 释放托管资源（如WebClient）
                _webClient?.Dispose();
            }

            _disposed = true;
        }

        // 析构函数（可选，防止未手动调用Dispose）
        ~KeyChecker()
        {
            Dispose(false);
        }

        #endregion
    }

    #region 配套实体类
    /// <summary>
    /// 产品密钥解析数据
    /// </summary>
    public class ProductKeyData
    {
        public uint Group { get; set; }      // 20位
        public ulong Serial { get; set; }    // 30位
        public ulong Security { get; set; }  // 53位
        public int Upgrade { get; set; }     // 1位（0/1）
    }
    // 单密钥处理结果（替换record为class）
    public class KeyResult
    {
        public string HResult { get; private set; }
        public string Message { get; private set; }
        public bool Success { get; private set; }

        public KeyResult(string hResult, string message, bool success)
        {
            HResult = hResult;
            Message = message;
            Success = success;
        }
    }

    // 批量处理结果（替换record为class）
    public class BatchResult
    {
        public List<string> ValidKeys { get; private set; }
        public int TotalCount { get; private set; }

        public BatchResult(List<string> validKeys, int totalCount)
        {
            ValidKeys = validKeys;
            TotalCount = totalCount;
        }
    }

    /// <summary>
    /// 产品密钥解析器（骨架，需补充PKEY2009解析逻辑）
    /// </summary>
    public static class ProductKeyDecoder
    {
        // 包含 N 的 25 位字符表
        private static readonly string Base32Table = "BCDFGHJKMNPQRTVWXY2346789";

        public static ProductKeyData Decode(string pkey)
        {
            // 1. 预处理
            string cleanKey = pkey.Replace("-", "").Replace(" ", "").ToUpperInvariant();
            if (cleanKey.Length != 25) throw new ArgumentException("密钥长度应为25位");

            // 2. 核心：大数幂运算 (Polynomial Base 25)
            // 从左往右读，每读一位：总和 = 总和 * 25 + 当前字符索引
            BigInteger combined = 0;
            foreach (char c in cleanKey)
            {
                int value = Base32Table.IndexOf(c);
                if (value == -1) throw new ArgumentException($"无效字符: {c}");

                // 关键：必须乘 25，因为字符表长度是 25
                combined = BigInteger.Multiply(combined, 25);
                combined = BigInteger.Add(combined, value);
            }

            // 3. 位拆分 (严格按照微软 PKEY2009 掩码)
            // Upgrade: 最低 1 位
            int upgrade = (int)(combined & 1);

            // Serial: 接下来的 30 位
            BigInteger serialMask = (BigInteger.One << 30) - 1;
            ulong serial = (ulong)((combined >> 1) & serialMask);

            // Group: 接下来的 20 位 (这里必须解出 4307)
            BigInteger groupMask = (BigInteger.One << 20) - 1;
            uint group = (uint)((combined >> 31) & groupMask);

            // Security: 接下来的 53 位
            BigInteger securityMask = (BigInteger.One << 53) - 1;
            ulong security = (ulong)((combined >> 51) & securityMask);

            return new ProductKeyData
            {
                Group = group,
                Serial = serial,
                Security = security,
                Upgrade = upgrade
            };
        }
    }

    /// <summary>
    /// PKeyConfig配置项
    /// </summary>
    public class PKeyConfigItem
    {
        public uint Group { get; set; }
        public string ConfigId { get; set; } = string.Empty;
    }

    /// <summary>
    /// PKeyConfig配置解析器（骨架，需补充XML解析逻辑）
    /// </summary>
    public class PKeyConfig
    {
        private readonly List<PKeyConfigItem> _configs = new List<PKeyConfigItem>();

        public PKeyConfig(XDocument xDoc)
        {
            ParseConfig(xDoc);
        }

        /// <summary>
        /// 解析pkeyconfig.xrm-ms XML
        /// </summary>
        /// <param name="xDoc">XML文档</param>
        public class ProductKeyConfigInfo
        {
            /// <summary>
            /// 配置唯一ID（ActConfigId）
            /// </summary>
            public string ActConfigId { get; set; }
            /// <summary>
            /// 引用组ID（RefGroupId）
            /// </summary>
            public string RefGroupId { get; set; }
            /// <summary>
            /// 产品描述（如 Windows Server 2019 RTM）
            /// </summary>
            public string ProductDescription { get; set; }
            /// <summary>
            /// 密钥类型（如 Retail、VOL:GVLK、OEM:NONSLP）
            /// </summary>
            public string KeyType { get; set; }
            /// <summary>
            /// 是否零售激活（IsRetailActivation）
            /// </summary>
            public bool IsRetailActivation { get; set; }
        }

        private void ParseConfig1(XDocument xDoc)
        {
            if (xDoc == null || xDoc.Root == null)
                throw new ArgumentNullException(nameof(xDoc), "XML文档为空或无根节点");

            // 定义命名空间
            XNamespace nsRg = "urn:mpeg:mpeg21:2003:01-REL-R-NS";
            XNamespace nsR = "urn:mpeg:mpeg21:2003:01-REL-R-NS";
            XNamespace nsTm = "http://www.microsoft.com/DRM/XrML2/TM/v2";

            // 修正节点查询逻辑：正确组合?.和??，避免类型转换错误
            var configNodes = xDoc.Root
                .Element(nsRg + "license") // 查找 r:license 节点（使用nsRg命名空间）
                ?.Element(nsR + "details")  // 查找 r:details 节点（使用nsR命名空间）
                ?.Descendants(nsTm + "infoTables") // 遍历 tm:infoTables 节点
                ?.Descendants("Configurations")   // 查找 Configurations 节点
                ?.Elements("Configuration")       // 提取所有 Configuration 子节点
                ?? Enumerable.Empty<XElement>(); // 空值兜底

            if (!configNodes.Any())
            {
                Console.WriteLine("未找到任何配置节点（Configuration）");
                return;
            }

            // 3. 遍历配置节点，提取核心信息
            List<ProductKeyConfigInfo> configList = new List<ProductKeyConfigInfo>();
            foreach (var configNode in configNodes)
            {
                var configInfo = new ProductKeyConfigInfo
                {
                    // 提取 ActConfigId（去除大括号 {}）
                    ActConfigId = configNode.Element("ActConfigId")?.Value?.Trim('{', '}') ?? "未知",
                    // 提取 RefGroupId
                    RefGroupId = configNode.Element("RefGroupId")?.Value ?? "未知",
                    // 提取 ProductDescription
                    ProductDescription = configNode.Element("ProductDescription")?.Value ?? "未描述",
                    // 提取 KeyType（ProductKeyType）
                    KeyType = configNode.Element("ProductKeyType")?.Value ?? "未知",
                    // 提取 IsRetailActivation（默认 false，非 Retail 类型均视为非零售）
                    IsRetailActivation = configNode.Element("ProductKeyType")?.Value.Equals("Retail", StringComparison.OrdinalIgnoreCase) ?? false
                };
                configList.Add(configInfo);
            }

            // 4. 结果处理（此处示例为打印，可根据需求替换为存储/进一步业务逻辑）
            Console.WriteLine($"共解析到 {configList.Count} 个产品密钥配置：");
            foreach (var config in configList)
            {
                Console.WriteLine($"=================================");
                Console.WriteLine($"配置ID：{config.ActConfigId}");
                Console.WriteLine($"引用组ID：{config.RefGroupId}");
                Console.WriteLine($"产品描述：{config.ProductDescription}");
                Console.WriteLine($"密钥类型：{config.KeyType}");
                Console.WriteLine($"是否零售：{config.IsRetailActivation}");
            }
        }
        private void ParseConfig(XDocument xDoc)
        {
            try
            {
                // 1. 定义 XrML 相关的命名空间
                XNamespace tm = "http://www.microsoft.com/DRM/XrML2/TM/v2";
                XNamespace pkcNs = "http://www.microsoft.com/DRM/PKEY/Configuration/2.0";

                // 2. 提取 Base64 编码的二进制配置数据 (pkeyConfigData)
                var binElement = xDoc.Descendants(tm + "infoBin")
                    .FirstOrDefault(e => (string)e.Attribute("name") == "pkeyConfigData");

                if (binElement == null || string.IsNullOrEmpty(binElement.Value))
                    throw new Exception("未在文件中找到 pkeyConfigData 节点。");

                // 3. 解码 Base64 字符串
                byte[] decodedBytes = Convert.FromBase64String(binElement.Value);
                string innerXml = Encoding.UTF8.GetString(decodedBytes);

                // 4. 解析内部的 XML 配置
                XDocument innerDoc = XDocument.Parse(innerXml);

                // 5. 提取所有的 Configuration 条目
                // 内部结构：<Configurations><Configuration><ActConfigId>...<RefGroupId>...
                var items = innerDoc.Descendants(pkcNs + "Configuration")
                    .Select(e => new PKeyConfigItem
                    {
                        // Group 对应 XML 中的 RefGroupId
                        Group = uint.Parse(e.Element(pkcNs + "RefGroupId")?.Value ?? "0"),
                        // ConfigId 对应 XML 中的 ActConfigId
                        ConfigId = e.Element(pkcNs + "ActConfigId")?.Value ?? string.Empty
                    })
                    .Where(x => x.Group > 0)
                    .ToList();

                if (items.Count > 0)
                {
                    _configs.AddRange(items);
                }
            }
            catch (Exception ex)
            {
                throw new Exception("解析 PKeyConfig 失败: " + ex.Message, ex);
            }
        }

        /// <summary>
        /// 根据Group获取配置
        /// </summary>
        /// <param name="group">Group值</param>
        /// <returns>配置项</returns>
        public PKeyConfigItem GetConfigForGroup(uint group)
        {
            var config = _configs.FirstOrDefault(c => c.Group == group);
            if (config == null)
            {
                throw new KeyNotFoundException($"当前pkeyconfig中无Group {group}对应的配置，请更换匹配的配置文件");
            }
            return config;
        }
    }

    /// <summary>
    /// .NET 4.8 兼容工具类
    /// </summary>
    public static class Utils
    {
        /// <summary>
        /// 格式化UTC时间戳
        /// </summary>
        public static string FormatTimestamp(DateTime dt)
        {
            return dt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
        }

        /// <summary>
        /// 生成Binding（.NET 4.8 兼容）
        /// </summary>
        public static string GenerateBinding()
        {
            // 16进制转字节数组
            var fixedBytes = HexStringToBytes("2A0000000100020001000100000000000000010001000100");

            // 生成18位随机字节（.NET 4.8 写法）
            var randomBytes = new byte[18];
            RandomNumberGenerator.Create().GetBytes(randomBytes);

            // 拼接固定字节和随机字节
            var binding = new byte[fixedBytes.Length + randomBytes.Length];
            Buffer.BlockCopy(fixedBytes, 0, binding, 0, fixedBytes.Length);
            Buffer.BlockCopy(randomBytes, 0, binding, fixedBytes.Length, randomBytes.Length);

            return Convert.ToBase64String(binding);
        }

        /// <summary>
        /// 编码激活数据
        /// </summary>
        public static string EncodeKeyData(uint group, ulong serial, ulong security, int upgrade)
        {
            var actHash = (ulong)upgrade & 1;
            actHash |= ((ulong)serial & ((1UL << 30) - 1)) << 1;
            actHash |= ((ulong)group & ((1UL << 20) - 1)) << 31;
            actHash |= ((ulong)security & ((1UL << 53) - 1)) << 51;

            // 转13字节小端
            var actBytes = new byte[13];
            for (int i = 0; i < 13; i++)
            {
                actBytes[i] = (byte)(actHash >> (8 * i));
            }
            return Convert.ToBase64String(actBytes);
        }

        /// <summary>
        /// XML特殊字符转义（.NET 4.8 兼容）
        /// </summary>
        public static string XmlEscape(string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            return input
                .Replace("&", "&amp;")
                .Replace("<", "&lt;")
                .Replace(">", "&gt;")
                .Replace("\"", "&quot;")
                .Replace("'", "&apos;");
        }

        /// <summary>
        /// 16进制字符串转字节数组（.NET 4.8 兼容）
        /// </summary>
        private static byte[] HexStringToBytes(string hex)
        {
            if (hex.Length % 2 != 0)
            {
                throw new ArgumentException("16进制字符串长度必须是偶数", nameof(hex));
            }

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }

        /// <summary>
        /// 读取XML文件为XDocument
        /// </summary>
        public static XDocument ReadXmlFile(string path)
        {
            return XDocument.Load(path, LoadOptions.PreserveWhitespace);
        }

    }
    #endregion

    
}