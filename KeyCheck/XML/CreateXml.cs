using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Xml.Linq;

namespace GenerateXML
{
    /// <summary>
    /// CreateXml 类（需要new 创建对象调用）负责构建并发送 XML 请求到 Microsoft 激活服务，并解析响应以获取产品密钥验证结果。
    /// </summary>
    public class CreateXml : IDisposable
    {
        private readonly HttpClient _httpClient;
        private bool _disposed = false;

        public CreateXml()
        {
            // .NET4.8 SSL/TLS 全局配置（保留原有忽略证书）
            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;

            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = true,
                UseCookies = false
            };

            _httpClient = new HttpClient(handler);
            _httpClient.DefaultRequestHeaders.Accept.Clear();
            _httpClient.DefaultRequestHeaders.Accept.Add(MediaTypeWithQualityHeaderValue.Parse("text/*"));
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("SLSSoapClient");
        }
        /// <summary>
        /// 获取产品密钥验证结果的核心方法。它构建一个符合 Microsoft 激活服务要求的 XML 请求，发送到指定的 SOAP 端点，并解析响应以提取 HRESULT 和 Message 信息。
        /// </summary>
        /// <param name="pkey"></param>
        /// <param name="actConfigId"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public KeyResult SendXML(string pkey, string actConfigId)
        {
            try
            {
                var now = DateTime.Now;
                var timestamp = Utils.FormatTimestamp(now);
                var secureStoreId = Guid.NewGuid().ToString();
                var binding = Utils.GenerateBinding();
                var ProductKeyType = string.IsNullOrEmpty(actConfigId)
                    ? "msft:rm/algorithm/pkey/2009"
                    : actConfigId.Contains("2009")
                        ? "msft:rm/algorithm/pkey/2009"
                        : "msft:rm/algorithm/pkey/2005";

                string processedPl;
                if (Office2021PublishLicense.StartsWith("&lt;"))
                {
                    processedPl = Office2021PublishLicense;
                }
                else
                {
                    processedPl = Utils.XmlEscape(Office2021PublishLicense);
                }

                var payload = AtoReqTemplate
                     .Replace("{plxml}", processedPl)
                    .Replace("{binding}", binding)
                    .Replace("{pkey}", pkey)
                    .Replace("{act_config_id}", System.Web.HttpUtility.HtmlEncode(actConfigId))
                    .Replace("{systime}", timestamp)
                    .Replace("{utctime}", timestamp)
                    .Replace("{secure_store_id}", secureStoreId)
                    .Replace("{ProductKeyType}", ProductKeyType);

                var url = "https://activation.sls.microsoft.com/SLActivateProduct/SLActivateProduct.asmx?configextension=o14";

                using (var content = new StringContent(payload, Encoding.UTF8, "text/xml"))
                {
                    content.Headers.ContentType = MediaTypeHeaderValue.Parse("text/xml; charset=utf-8");
                    _httpClient.DefaultRequestHeaders.Remove("SOAPAction");
                    _httpClient.DefaultRequestHeaders.Add("SOAPAction", "http://microsoft.com/SL/ProductActivationService/IssueToken");

                    string respXml;
                    try
                    {
                        // 同步POST，完全对齐原WebClient行为
                        var response = _httpClient.PostAsync(url, content).Result;
                        // .NET 4.8 中，即使状态码非200，也能通过response读取内容（无需抛异常）
                        respXml = response.Content.ReadAsStringAsync().Result;
                    }
                    catch (AggregateException ex)
                    {
                        var innerEx = ex.InnerException;
                        // 处理网络异常/无响应场景
                        if (innerEx is HttpRequestException)
                        {
                            // .NET 4.8 HttpRequestException 无Response属性，直接抛出网络错误
                            throw new Exception("网络连接失败，未收到服务器响应", innerEx);
                        }
                        // 其他异常直接抛出
                        throw;
                    }
                    catch (HttpRequestException ex)
                    {
                        // 直接捕获HttpRequestException，处理网络错误
                        throw new Exception("网络连接失败，未收到服务器响应", ex);
                    }

                    return ParseSoapResponse(respXml);
                }
            }
            catch (Exception ex)
            {
                return new KeyResult("N/A", $"Product key not compatible with provided pkeyconfig: {ex.Message}", false);
            }
        }

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

                // 1. 查找 Fault 节点 (忽略命名空间)
                var faultNode = xDoc.Descendants().FirstOrDefault(x => x.Name.LocalName == "Fault");

                if (faultNode == null)
                {
                    return new KeyResult("0x0", "Success", true);
                }

                // 2. 查找 detail 节点
                var detailNode = faultNode.Descendants().FirstOrDefault(x => x.Name.LocalName == "detail");

                // 3. 提取 HRESULT
                // 这里的关键：HRESULT 是 detail 的直接或间接子级
                var hresult = detailNode?.Elements().FirstOrDefault(x => x.Name.LocalName == "HRESULT")?.Value
                              ?? "N/A";

                // 4. 提取 Message
                // 路径：detail -> Messages -> Message
                var messageNode = detailNode?.Descendants()
                                            .FirstOrDefault(x => x.Name.LocalName == "Message");

                string rawMessage = messageNode?.Value ?? "Unknown Error";

                // 5. 格式化清理
                // 注意：XML 解析器会自动把 &gt; 转回 >，手动 Replace 可能不需要，
                // 但为了保险可以处理常见的混淆字符。
                string cleanMessage = rawMessage
                    .Replace("\n", " ")
                    .Replace("\r", "")
                    .Replace("---&gt;", "->")
                    .Trim();

                return new KeyResult(hresult, cleanMessage, false);
            }
            catch (Exception ex)
            {
                return new KeyResult("Error", $"XML 解析异常: {ex.Message}", false);
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;
            if (disposing)
            {
                _httpClient?.Dispose();
            }
            _disposed = true;
        }

        ~CreateXml()
        {
            Dispose(false);
        }
        string Office2009PublishLicense = @"&lt;?xml version=""1.0"" encoding=""utf-8""?&gt;&lt;rg:licenseGroup
                            xmlns:rg=""urn:mpeg:mpeg21:2003:01-REL-R-NS""&gt;&lt;r:license
                            xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS"" licenseId=""{7c6134e6-409c-47ed-a9b5-514c983557a0}""
                            xmlns:sx=""urn:mpeg:mpeg21:2003:01-REL-SX-NS""
                            xmlns:mx=""urn:mpeg:mpeg21:2003:01-REL-MX-NS""
                            xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2""
                            xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""&gt;&lt;r:title&gt;Office 16 Publishing License (Public)&lt;/r:title&gt;&lt;r:grant&gt;&lt;r:forAll varName=""productId""&gt;&lt;r:anXmlExpression&gt;/sl:productId/sl:pid&lt;/r:anXmlExpression&gt;&lt;/r:forAll&gt;&lt;r:forAll varName=""binding""&gt;&lt;/r:forAll&gt;&lt;r:keyHolder&gt;&lt;r:info&gt;&lt;KeyValue
                            xmlns=""http://www.w3.org/2000/09/xmldsig#""&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;uzDfZ3WsHY4/UKthrglDqsLw4BqrlOWlNdLBnLD/5sdAUXnv+2kB9jJJPK2TYkbkQ5bfK4QfS8h050WPtpN/NGL7batTKnEjNnRNrenM8+YAT9Ne7K7xCwgJdb08rOZyMqQPKtPr1p6FCwPY7zBvOmtNdvVs0psxwEuq2DmFz1g8+WJw9zGgqI4qkYA7P/yaN0lbQpvH3p1v68DogX7BLd6Z+Z+3MNG1Lh+k11kmd+lM8RaLq74zT8OSZDJ9McD9i/4JaB0kJfdV5oGb0ZbWvW/3Z8pQVf7tA5s3J1Tpp3/nrvV5WtZMZ3nGemTFRP5dxbH5y4YSBoKFGOYCyQH3pQ==&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/r:info&gt;&lt;/r:keyHolder&gt;&lt;r:issue/&gt;&lt;r:grant&gt;&lt;r:forAll varName=""application""&gt;&lt;r:anXmlExpression&gt;editionId[@value="""" or @value=""Office16ProPlusMSDNR_Retail""]&lt;/r:anXmlExpression&gt;&lt;/r:forAll&gt;&lt;r:forAll varName=""appid""&gt;&lt;r:propertyPossessor&gt;&lt;tm:application varRef=""application""/&gt;&lt;r:trustedRootIssuers&gt;&lt;r:keyHolder&gt;&lt;r:info&gt;&lt;KeyValue
                            xmlns=""http://www.w3.org/2000/09/xmldsig#""&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;lAi6wXhcWOjn1rN1aIy6z4YBcYlkdrxP9EEw7iiD0tg6i0aVOgZ/FS6IxiOgZXYwTgK/BHA7QN6/lvxnecZ2cETT7w7ZRByGUN1zTQKFwXdyQz/xdp5kZ81bmI3EQWLJBT6iW5K8HZr0qRsQRlExUrWZSOI449+Br2QgOMcBMS3FEMBS8XCBPgZ3z/V9ydztWjhopBB0ZngebWEjqwtlrXEB1M+WOPWUcljdJlp5pXNkiqCrJEzenMJ+tfTfD/8zv08LdhhIAmx1VLViItRqO9OD7l313X7bVyfTWTxGmf7D9YS5Sa0UCiOXM0qVZCVuQ5CzjLRLa13FaJurQ6SBhQ==&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/r:info&gt;&lt;/r:keyHolder&gt;&lt;/r:trustedRootIssuers&gt;&lt;/r:propertyPossessor&gt;&lt;/r:forAll&gt;&lt;r:keyHolder&gt;&lt;r:info&gt;&lt;KeyValue
                            xmlns=""http://www.w3.org/2000/09/xmldsig#""&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;ptV5l33YkYwdOV/Ru16t2VcbVg92rhNO1ng3kIn/AY/c/HlfUuVxwR4F4F3JoxbDQ4wiNf1QwQaAJdl/1pHy0iY3Hb60KLMuqOb4/C2EsICU2cOuhVxgVIoM+aqEkkFHyUx1E6+TbCSAvv0PQR7ns6h9CLlXPHZ6w6P8s0L/rAs=&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/r:info&gt;&lt;/r:keyHolder&gt;&lt;sl:runSoftware/&gt;&lt;sl:appId varRef=""appid""/&gt;&lt;r:allConditions&gt;&lt;r:allConditions&gt;&lt;sl:productPolicies
                            xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2""&gt;&lt;sl:priority&gt;400&lt;/sl:priority&gt;&lt;sl:policyStr name=""Security-SPP-Reserved-ProductUniquenessGroupID""&gt;05DC53C7-C5BE-4D6B-9A3E-1984B2E7F47C&lt;/sl:policyStr&gt;&lt;sl:policyStr name=""Security-SPP-Reserved-Family"" attributes=""override-only""&gt;Office16ProPlusMSDNR_Retail&lt;/sl:policyStr&gt;&lt;/sl:productPolicies&gt;&lt;sl:proxyExecutionKey
                            xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2""&gt;&lt;/sl:proxyExecutionKey&gt;&lt;/r:allConditions&gt;&lt;mx:renderer&gt;&lt;sl:binding varRef=""binding""/&gt;&lt;sl:productId varRef=""productId""/&gt;&lt;/mx:renderer&gt;&lt;/r:allConditions&gt;&lt;/r:grant&gt;&lt;r:allConditions&gt;&lt;sl:businessRules
                            xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2""&gt;&lt;/sl:businessRules&gt;&lt;/r:allConditions&gt;&lt;/r:grant&gt;&lt;r:issuer&gt;&lt;Signature
                            xmlns=""http://www.w3.org/2000/09/xmldsig#""&gt;&lt;SignedInfo&gt;&lt;CanonicalizationMethod Algorithm=""http://www.microsoft.com/xrml/lwc14n""/&gt;&lt;SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1""/&gt;&lt;Reference&gt;&lt;Transforms&gt;&lt;Transform Algorithm=""urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform""/&gt;&lt;Transform Algorithm=""http://www.microsoft.com/xrml/lwc14n""/&gt;&lt;/Transforms&gt;&lt;DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""/&gt;&lt;DigestValue&gt;TtnlPLgMGSKY+gXlVPTp9bLmY9U=&lt;/DigestValue&gt;&lt;/Reference&gt;&lt;/SignedInfo&gt;&lt;SignatureValue&gt;DcPeLWssKlnrpLhnt5r+v1SSSzTvaiLPMk9DZHsKFcq7wD7umhzIw6+BnasQK20EvfZkXbQtzskBjRsZ+DXxUgp4F/CGTk7bWRDN//XQOHOP1BPyVhNVylcqjQw3K7ZKVtsbWDpzOskp9Rc28mh/XUhKyMyueFpFeKGhC7pbwMi0pk0JcFEyCwbiCYTYx9bCSipKx1JI5DpSfCZdql6X7JOsdiTjQYVvcLzkstwWmc2OCZgZexMdPB7Td5f3YR6kHfFOXP9Q7EIxsCXgDMw1L1VpJwOtXnCX/qntd9Z2XvilFv6CtJetndKafZEBzyz+997l6Iv9pL5cqs62TwhSPw==&lt;/SignatureValue&gt;&lt;KeyInfo&gt;&lt;KeyValue&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;lAi6wXhcWOjn1rN1aIy6z4YBcYlkdrxP9EEw7iiD0tg6i0aVOgZ/FS6IxiOgZXYwTgK/BHA7QN6/lvxnecZ2cETT7w7ZRByGUN1zTQKFwXdyQz/xdp5kZ81bmI3EQWLJBT6iW5K8HZr0qRsQRlExUrWZSOI449+Br2QgOMcBMS3FEMBS8XCBPgZ3z/V9ydztWjhopBB0ZngebWEjqwtlrXEB1M+WOPWUcljdJlp5pXNkiqCrJEzenMJ+tfTfD/8zv08LdhhIAmx1VLViItRqO9OD7l313X7bVyfTWTxGmf7D9YS5Sa0UCiOXM0qVZCVuQ5CzjLRLa13FaJurQ6SBhQ==&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/KeyInfo&gt;&lt;/Signature&gt;&lt;r:details&gt;&lt;r:timeOfIssue&gt;2018-06-27T23:08:05Z&lt;/r:timeOfIssue&gt;&lt;/r:details&gt;&lt;/r:issuer&gt;&lt;r:otherInfo
                            xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS""&gt;&lt;tm:infoTables
                            xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""&gt;&lt;tm:infoList tag=""#global""&gt;&lt;tm:infoStr name=""licenseType""&gt;msft:sl/PL/GENERIC/PUBLIC&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""licenseVersion""&gt;2.0&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""licensorUrl""&gt;https://licensing.microsoft.com&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""licenseCategory""&gt;msft:sl/PL/GENERIC/PUBLIC&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""productSkuId""&gt;{84832881-46EF-4124-8ABC-EB493CDCF78E}&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""privateCertificateId""&gt;{997cb5ed-bf97-40c8-857a-19945436aa99}&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""applicationId""&gt;{0ff1ce15-a989-479d-af46-f275c6370663}&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""productName""&gt;Office 16, Office16ProPlusMSDNR_Retail edition&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""Family""&gt;Office16ProPlusMSDNR_Retail&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""productAuthor""&gt;Microsoft Corporation&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""productDescription""&gt;Office 16&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""clientIssuanceCertificateId""&gt;{CE939C0E-53F7-4011-A286-78B6975FA5F0}&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""hwid:ootGrace""&gt;3&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""migratable""&gt;true&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""referralData""&gt;ReferralId=000000;PartnerId=00000000-0000-0000-0000-000000000000&lt;/tm:infoStr&gt;&lt;/tm:infoList&gt;&lt;/tm:infoTables&gt;&lt;/r:otherInfo&gt;&lt;/r:license&gt;&lt;r:license
                            xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS"" licenseId=""{997cb5ed-bf97-40c8-857a-19945436aa99}""
                            xmlns:sx=""urn:mpeg:mpeg21:2003:01-REL-SX-NS""
                            xmlns:mx=""urn:mpeg:mpeg21:2003:01-REL-MX-NS""
                            xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2""
                            xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""&gt;&lt;r:title&gt;Office 16 Publishing License (Private)&lt;/r:title&gt;&lt;r:grant&gt;&lt;r:keyHolder&gt;&lt;r:info&gt;&lt;KeyValue
                            xmlns=""http://www.w3.org/2000/09/xmldsig#""&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;uzDfZ3WsHY4/UKthrglDqsLw4BqrlOWlNdLBnLD/5sdAUXnv+2kB9jJJPK2TYkbkQ5bfK4QfS8h050WPtpN/NGL7batTKnEjNnRNrenM8+YAT9Ne7K7xCwgJdb08rOZyMqQPKtPr1p6FCwPY7zBvOmtNdvVs0psxwEuq2DmFz1g8+WJw9zGgqI4qkYA7P/yaN0lbQpvH3p1v68DogX7BLd6Z+Z+3MNG1Lh+k11kmd+lM8RaLq74zT8OSZDJ9McD9i/4JaB0kJfdV5oGb0ZbWvW/3Z8pQVf7tA5s3J1Tpp3/nrvV5WtZMZ3nGemTFRP5dxbH5y4YSBoKFGOYCyQH3pQ==&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/r:info&gt;&lt;/r:keyHolder&gt;&lt;r:issue/&gt;&lt;r:grant&gt;&lt;r:forAll varName=""anyRight""&gt;&lt;/r:forAll&gt;&lt;r:forAll varName=""appid""&gt;&lt;/r:forAll&gt;&lt;r:keyHolder&gt;&lt;r:info&gt;&lt;KeyValue
                            xmlns=""http://www.w3.org/2000/09/xmldsig#""&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;ptV5l33YkYwdOV/Ru16t2VcbVg92rhNO1ng3kIn/AY/c/HlfUuVxwR4F4F3JoxbDQ4wiNf1QwQaAJdl/1pHy0iY3Hb60KLMuqOb4/C2EsICU2cOuhVxgVIoM+aqEkkFHyUx1E6+TbCSAvv0PQR7ns6h9CLlXPHZ6w6P8s0L/rAs=&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/r:info&gt;&lt;/r:keyHolder&gt;&lt;tm:decryptContent/&gt;&lt;tm:symmetricKey&gt;&lt;tm:AESKeyValue size=""16""&gt;AAAAAAAAAAAAAAAAAAAAAA==&lt;/tm:AESKeyValue&gt;&lt;/tm:symmetricKey&gt;&lt;r:prerequisiteRight&gt;&lt;r:keyHolder&gt;&lt;r:info&gt;&lt;KeyValue
                            xmlns=""http://www.w3.org/2000/09/xmldsig#""&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;ptV5l33YkYwdOV/Ru16t2VcbVg92rhNO1ng3kIn/AY/c/HlfUuVxwR4F4F3JoxbDQ4wiNf1QwQaAJdl/1pHy0iY3Hb60KLMuqOb4/C2EsICU2cOuhVxgVIoM+aqEkkFHyUx1E6+TbCSAvv0PQR7ns6h9CLlXPHZ6w6P8s0L/rAs=&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/r:info&gt;&lt;/r:keyHolder&gt;&lt;r:right varRef=""anyRight""/&gt;&lt;sl:appId varRef=""appid""/&gt;&lt;r:trustedRootIssuers&gt;&lt;r:keyHolder&gt;&lt;r:info&gt;&lt;KeyValue
                            xmlns=""http://www.w3.org/2000/09/xmldsig#""&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;uzDfZ3WsHY4/UKthrglDqsLw4BqrlOWlNdLBnLD/5sdAUXnv+2kB9jJJPK2TYkbkQ5bfK4QfS8h050WPtpN/NGL7batTKnEjNnRNrenM8+YAT9Ne7K7xCwgJdb08rOZyMqQPKtPr1p6FCwPY7zBvOmtNdvVs0psxwEuq2DmFz1g8+WJw9zGgqI4qkYA7P/yaN0lbQpvH3p1v68DogX7BLd6Z+Z+3MNG1Lh+k11kmd+lM8RaLq74zT8OSZDJ9McD9i/4JaB0kJfdV5oGb0ZbWvW/3Z8pQVf7tA5s3J1Tpp3/nrvV5WtZMZ3nGemTFRP5dxbH5y4YSBoKFGOYCyQH3pQ==&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/r:info&gt;&lt;/r:keyHolder&gt;&lt;/r:trustedRootIssuers&gt;&lt;/r:prerequisiteRight&gt;&lt;/r:grant&gt;&lt;/r:grant&gt;&lt;r:issuer&gt;&lt;Signature
                            xmlns=""http://www.w3.org/2000/09/xmldsig#""&gt;&lt;SignedInfo&gt;&lt;CanonicalizationMethod Algorithm=""http://www.microsoft.com/xrml/lwc14n""/&gt;&lt;SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1""/&gt;&lt;Reference&gt;&lt;Transforms&gt;&lt;Transform Algorithm=""urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform""/&gt;&lt;Transform Algorithm=""http://www.microsoft.com/xrml/lwc14n""/&gt;&lt;/Transforms&gt;&lt;DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""/&gt;&lt;DigestValue&gt;3bFwQHj4OtR0bjG1eiTQfZ0jFWQ=&lt;/DigestValue&gt;&lt;/Reference&gt;&lt;/SignedInfo&gt;&lt;SignatureValue&gt;NbYcpkEFJ1okOjpLKKktLnJsQ7lI3HG052adOCdhPf0qBxgXFTW25k+NFwp1UELR3ls2R57/3QJsSu1fjxjarpHVud4i22jou5+bMrDok5J0V6oPFaYBJce6Mjw8xcpBOZczqMfUhAa/PeYvJSG8wAi/2Wthco6Gt5dwVxFEQc7Zpr7pH3OxZz4ujKH/4WcgyjjlrwvW8IQ2Xfbcl562K449G1VOmB2G1XwfdSFCliJiO2FV44Ztk0gPkBNHcjrC08TipMTGbqJH8tQn4VJ5zueoMoxCCLMPQ/kVW4wjS5VGfWTEIzvvy2OSdY3tdnt4b3dbMBMVRixXVn0Cp2kh1Q==&lt;/SignatureValue&gt;&lt;KeyInfo&gt;&lt;KeyValue&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;lAi6wXhcWOjn1rN1aIy6z4YBcYlkdrxP9EEw7iiD0tg6i0aVOgZ/FS6IxiOgZXYwTgK/BHA7QN6/lvxnecZ2cETT7w7ZRByGUN1zTQKFwXdyQz/xdp5kZ81bmI3EQWLJBT6iW5K8HZr0qRsQRlExUrWZSOI449+Br2QgOMcBMS3FEMBS8XCBPgZ3z/V9ydztWjhopBB0ZngebWEjqwtlrXEB1M+WOPWUcljdJlp5pXNkiqCrJEzenMJ+tfTfD/8zv08LdhhIAmx1VLViItRqO9OD7l313X7bVyfTWTxGmf7D9YS5Sa0UCiOXM0qVZCVuQ5CzjLRLa13FaJurQ6SBhQ==&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/KeyInfo&gt;&lt;/Signature&gt;&lt;r:details&gt;&lt;r:timeOfIssue&gt;2018-06-27T23:08:05Z&lt;/r:timeOfIssue&gt;&lt;/r:details&gt;&lt;/r:issuer&gt;&lt;r:otherInfo
                            xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS""&gt;&lt;tm:infoTables
                            xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""&gt;&lt;tm:infoList tag=""#global""&gt;&lt;tm:infoStr name=""licenseType""&gt;msft:sl/PL/GENERIC/PRIVATE&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""licenseVersion""&gt;2.0&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""licensorUrl""&gt;https://licensing.microsoft.com&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""licenseCategory""&gt;msft:sl/PL/GENERIC/PRIVATE&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""publicCertificateId""&gt;{7c6134e6-409c-47ed-a9b5-514c983557a0}&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""clientIssuanceCertificateId""&gt;{CE939C0E-53F7-4011-A286-78B6975FA5F0}&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""hwid:ootGrace""&gt;3&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""migratable""&gt;true&lt;/tm:infoStr&gt;&lt;/tm:infoList&gt;&lt;/tm:infoTables&gt;&lt;/r:otherInfo&gt;&lt;/r:license&gt;&lt;/rg:licenseGroup&gt;
                        ";
        string Office2021PublishLicense = @"&lt;?xml version=""1.0"" encoding=""utf-8""?&gt;&lt;rg:licenseGroup
xmlns:rg=""urn:mpeg:mpeg21:2003:01-REL-R-NS""&gt;&lt;r:license
xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS"" licenseId=""{94f767e4-6a67-4c92-9d5c-2949e6973a26}""
xmlns:sx=""urn:mpeg:mpeg21:2003:01-REL-SX-NS""
xmlns:mx=""urn:mpeg:mpeg21:2003:01-REL-MX-NS""
xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2""
xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""&gt;&lt;r:title&gt;Office 21 Publishing License (Public)&lt;/r:title&gt;&lt;r:grant&gt;&lt;r:forAll varName=""productId""&gt;&lt;r:anXmlExpression&gt;/sl:productId/sl:pid&lt;/r:anXmlExpression&gt;&lt;/r:forAll&gt;&lt;r:forAll varName=""binding""&gt;&lt;/r:forAll&gt;&lt;r:keyHolder&gt;&lt;r:info&gt;&lt;KeyValue
xmlns=""http://www.w3.org/2000/09/xmldsig#""&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;uzDfZ3WsHY4/UKthrglDqsLw4BqrlOWlNdLBnLD/5sdAUXnv+2kB9jJJPK2TYkbkQ5bfK4QfS8h050WPtpN/NGL7batTKnEjNnRNrenM8+YAT9Ne7K7xCwgJdb08rOZyMqQPKtPr1p6FCwPY7zBvOmtNdvVs0psxwEuq2DmFz1g8+WJw9zGgqI4qkYA7P/yaN0lbQpvH3p1v68DogX7BLd6Z+Z+3MNG1Lh+k11kmd+lM8RaLq74zT8OSZDJ9McD9i/4JaB0kJfdV5oGb0ZbWvW/3Z8pQVf7tA5s3J1Tpp3/nrvV5WtZMZ3nGemTFRP5dxbH5y4YSBoKFGOYCyQH3pQ==&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/r:info&gt;&lt;/r:keyHolder&gt;&lt;r:issue/&gt;&lt;r:grant&gt;&lt;r:forAll varName=""application""&gt;&lt;r:anXmlExpression&gt;editionId[@value="""" or @value=""Office21ProPlus2021MSDNR_Retail""]&lt;/r:anXmlExpression&gt;&lt;/r:forAll&gt;&lt;r:forAll varName=""appid""&gt;&lt;r:propertyPossessor&gt;&lt;tm:application varRef=""application""/&gt;&lt;r:trustedRootIssuers&gt;&lt;r:keyHolder&gt;&lt;r:info&gt;&lt;KeyValue
xmlns=""http://www.w3.org/2000/09/xmldsig#""&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;lAi6wXhcWOjn1rN1aIy6z4YBcYlkdrxP9EEw7iiD0tg6i0aVOgZ/FS6IxiOgZXYwTgK/BHA7QN6/lvxnecZ2cETT7w7ZRByGUN1zTQKFwXdyQz/xdp5kZ81bmI3EQWLJBT6iW5K8HZr0qRsQRlExUrWZSOI449+Br2QgOMcBMS3FEMBS8XCBPgZ3z/V9ydztWjhopBB0ZngebWEjqwtlrXEB1M+WOPWUcljdJlp5pXNkiqCrJEzenMJ+tfTfD/8zv08LdhhIAmx1VLViItRqO9OD7l313X7bVyfTWTxGmf7D9YS5Sa0UCiOXM0qVZCVuQ5CzjLRLa13FaJurQ6SBhQ==&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/r:info&gt;&lt;/r:keyHolder&gt;&lt;/r:trustedRootIssuers&gt;&lt;/r:propertyPossessor&gt;&lt;/r:forAll&gt;&lt;r:keyHolder&gt;&lt;r:info&gt;&lt;KeyValue
xmlns=""http://www.w3.org/2000/09/xmldsig#""&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;ptV5l33YkYwdOV/Ru16t2VcbVg92rhNO1ng3kIn/AY/c/HlfUuVxwR4F4F3JoxbDQ4wiNf1QwQaAJdl/1pHy0iY3Hb60KLMuqOb4/C2EsICU2cOuhVxgVIoM+aqEkkFHyUx1E6+TbCSAvv0PQR7ns6h9CLlXPHZ6w6P8s0L/rAs=&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/r:info&gt;&lt;/r:keyHolder&gt;&lt;sl:runSoftware/&gt;&lt;sl:appId varRef=""appid""/&gt;&lt;r:allConditions&gt;&lt;r:allConditions&gt;&lt;sl:productPolicies
xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2""&gt;&lt;sl:priority&gt;400&lt;/sl:priority&gt;&lt;sl:policyStr name=""Security-SPP-Reserved-ProductUniquenessGroupID""&gt;C6CFF4D8-13AE-4607-A1D9-955ADAF7DC87&lt;/sl:policyStr&gt;&lt;sl:policyStr name=""Security-SPP-Reserved-Family"" attributes=""override-only""&gt;Office21ProPlus2021MSDNR_Retail&lt;/sl:policyStr&gt;&lt;/sl:productPolicies&gt;&lt;sl:proxyExecutionKey
xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2""&gt;&lt;/sl:proxyExecutionKey&gt;&lt;/r:allConditions&gt;&lt;mx:renderer&gt;&lt;sl:binding varRef=""binding""/&gt;&lt;sl:productId varRef=""productId""/&gt;&lt;/mx:renderer&gt;&lt;/r:allConditions&gt;&lt;/r:grant&gt;&lt;r:allConditions&gt;&lt;sl:businessRules
xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2""&gt;&lt;/sl:businessRules&gt;&lt;/r:allConditions&gt;&lt;/r:grant&gt;&lt;r:issuer&gt;&lt;Signature
xmlns=""http://www.w3.org/2000/09/xmldsig#""&gt;&lt;SignedInfo&gt;&lt;CanonicalizationMethod Algorithm=""http://www.microsoft.com/xrml/lwc14n""/&gt;&lt;SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1""/&gt;&lt;Reference&gt;&lt;Transforms&gt;&lt;Transform Algorithm=""urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform""/&gt;&lt;Transform Algorithm=""http://www.microsoft.com/xrml/lwc14n""/&gt;&lt;/Transforms&gt;&lt;DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""/&gt;&lt;DigestValue&gt;VZeYFJYK0JR8txHtMehTGfpOBrM=&lt;/DigestValue&gt;&lt;/Reference&gt;&lt;/SignedInfo&gt;&lt;SignatureValue&gt;ffcRHzL78UNvQcNL5p1igM5eUadu+/PFQtdQU0IU6NZKE9dQnGTXfR0rIbN5VAmM1E/eywdyUArdoD9ETY6pyW+dhu+PhyTP33gP6eqypPudnCC3P2a+Sx0Fmk+zKkQ69TJZLOl2Mx2At5C3BZOU/NYrYYcqul6ImZ8dbRETO8Fd1znNxiT3WPr2dNdYuRobSbKwJgXwOnPASI2BEd44qpOcxUhNO/3IVf3jb0APnjQ8ryyBOew4wIGZqiSV0hWX4FBZpwtRjFfGpXj2Q8JWn00kNqffbNItcixbzEoecdj5tM3KsD1HGwjufvCAf1jYaapPxb72ZQC4FR3wrhinHQ==&lt;/SignatureValue&gt;&lt;KeyInfo&gt;&lt;KeyValue&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;lAi6wXhcWOjn1rN1aIy6z4YBcYlkdrxP9EEw7iiD0tg6i0aVOgZ/FS6IxiOgZXYwTgK/BHA7QN6/lvxnecZ2cETT7w7ZRByGUN1zTQKFwXdyQz/xdp5kZ81bmI3EQWLJBT6iW5K8HZr0qRsQRlExUrWZSOI449+Br2QgOMcBMS3FEMBS8XCBPgZ3z/V9ydztWjhopBB0ZngebWEjqwtlrXEB1M+WOPWUcljdJlp5pXNkiqCrJEzenMJ+tfTfD/8zv08LdhhIAmx1VLViItRqO9OD7l313X7bVyfTWTxGmf7D9YS5Sa0UCiOXM0qVZCVuQ5CzjLRLa13FaJurQ6SBhQ==&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/KeyInfo&gt;&lt;/Signature&gt;&lt;r:details&gt;&lt;r:timeOfIssue&gt;2025-03-01T00:17:10Z&lt;/r:timeOfIssue&gt;&lt;/r:details&gt;&lt;/r:issuer&gt;&lt;r:otherInfo
xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS""&gt;&lt;tm:infoTables
xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""&gt;&lt;tm:infoList tag=""#global""&gt;&lt;tm:infoStr name=""licenseType""&gt;msft:sl/PL/GENERIC/PUBLIC&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""licenseVersion""&gt;2.0&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""licensorUrl""&gt;https://licensing.microsoft.com&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""licenseCategory""&gt;msft:sl/PL/GENERIC/PUBLIC&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""productSkuId""&gt;{8D77DE46-78FB-428D-B8C4-C4A078E8912D}&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""privateCertificateId""&gt;{10514519-50c1-4a8f-b6ac-4581cd75ed11}&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""applicationId""&gt;{0ff1ce15-a989-479d-af46-f275c6370663}&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""productName""&gt;Office 21, Office21ProPlus2021MSDNR_Retail edition&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""Family""&gt;Office21ProPlus2021MSDNR_Retail&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""productAuthor""&gt;Microsoft Corporation&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""productDescription""&gt;Office 21&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""clientIssuanceCertificateId""&gt;{CE939C0E-53F7-4011-A286-78B6975FA5F0}&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""hwid:ootGrace""&gt;3&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""migratable""&gt;true&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""referralData""&gt;ReferralId=000000;PartnerId=00000000-0000-0000-0000-000000000000&lt;/tm:infoStr&gt;&lt;/tm:infoList&gt;&lt;/tm:infoTables&gt;&lt;/r:otherInfo&gt;&lt;/r:license&gt;&lt;r:license
xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS"" licenseId=""{10514519-50c1-4a8f-b6ac-4581cd75ed11}""
xmlns:sx=""urn:mpeg:mpeg21:2003:01-REL-SX-NS""
xmlns:mx=""urn:mpeg:mpeg21:2003:01-REL-MX-NS""
xmlns:sl=""http://www.microsoft.com/DRM/XrML2/SL/v2""
xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""&gt;&lt;r:title&gt;Office 21 Publishing License (Private)&lt;/r:title&gt;&lt;r:grant&gt;&lt;r:keyHolder&gt;&lt;r:info&gt;&lt;KeyValue
xmlns=""http://www.w3.org/2000/09/xmldsig#""&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;uzDfZ3WsHY4/UKthrglDqsLw4BqrlOWlNdLBnLD/5sdAUXnv+2kB9jJJPK2TYkbkQ5bfK4QfS8h050WPtpN/NGL7batTKnEjNnRNrenM8+YAT9Ne7K7xCwgJdb08rOZyMqQPKtPr1p6FCwPY7zBvOmtNdvVs0psxwEuq2DmFz1g8+WJw9zGgqI4qkYA7P/yaN0lbQpvH3p1v68DogX7BLd6Z+Z+3MNG1Lh+k11kmd+lM8RaLq74zT8OSZDJ9McD9i/4JaB0kJfdV5oGb0ZbWvW/3Z8pQVf7tA5s3J1Tpp3/nrvV5WtZMZ3nGemTFRP5dxbH5y4YSBoKFGOYCyQH3pQ==&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/r:info&gt;&lt;/r:keyHolder&gt;&lt;r:issue/&gt;&lt;r:grant&gt;&lt;r:forAll varName=""anyRight""&gt;&lt;/r:forAll&gt;&lt;r:forAll varName=""appid""&gt;&lt;/r:forAll&gt;&lt;r:keyHolder&gt;&lt;r:info&gt;&lt;KeyValue
xmlns=""http://www.w3.org/2000/09/xmldsig#""&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;ptV5l33YkYwdOV/Ru16t2VcbVg92rhNO1ng3kIn/AY/c/HlfUuVxwR4F4F3JoxbDQ4wiNf1QwQaAJdl/1pHy0iY3Hb60KLMuqOb4/C2EsICU2cOuhVxgVIoM+aqEkkFHyUx1E6+TbCSAvv0PQR7ns6h9CLlXPHZ6w6P8s0L/rAs=&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/r:info&gt;&lt;/r:keyHolder&gt;&lt;tm:decryptContent/&gt;&lt;tm:symmetricKey&gt;&lt;tm:AESKeyValue size=""16""&gt;AAAAAAAAAAAAAAAAAAAAAA==&lt;/tm:AESKeyValue&gt;&lt;/tm:symmetricKey&gt;&lt;r:prerequisiteRight&gt;&lt;r:keyHolder&gt;&lt;r:info&gt;&lt;KeyValue
xmlns=""http://www.w3.org/2000/09/xmldsig#""&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;ptV5l33YkYwdOV/Ru16t2VcbVg92rhNO1ng3kIn/AY/c/HlfUuVxwR4F4F3JoxbDQ4wiNf1QwQaAJdl/1pHy0iY3Hb60KLMuqOb4/C2EsICU2cOuhVxgVIoM+aqEkkFHyUx1E6+TbCSAvv0PQR7ns6h9CLlXPHZ6w6P8s0L/rAs=&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/r:info&gt;&lt;/r:keyHolder&gt;&lt;r:right varRef=""anyRight""/&gt;&lt;sl:appId varRef=""appid""/&gt;&lt;r:trustedRootIssuers&gt;&lt;r:keyHolder&gt;&lt;r:info&gt;&lt;KeyValue
xmlns=""http://www.w3.org/2000/09/xmldsig#""&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;uzDfZ3WsHY4/UKthrglDqsLw4BqrlOWlNdLBnLD/5sdAUXnv+2kB9jJJPK2TYkbkQ5bfK4QfS8h050WPtpN/NGL7batTKnEjNnRNrenM8+YAT9Ne7K7xCwgJdb08rOZyMqQPKtPr1p6FCwPY7zBvOmtNdvVs0psxwEuq2DmFz1g8+WJw9zGgqI4qkYA7P/yaN0lbQpvH3p1v68DogX7BLd6Z+Z+3MNG1Lh+k11kmd+lM8RaLq74zT8OSZDJ9McD9i/4JaB0kJfdV5oGb0ZbWvW/3Z8pQVf7tA5s3J1Tpp3/nrvV5WtZMZ3nGemTFRP5dxbH5y4YSBoKFGOYCyQH3pQ==&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/r:info&gt;&lt;/r:keyHolder&gt;&lt;/r:trustedRootIssuers&gt;&lt;/r:prerequisiteRight&gt;&lt;/r:grant&gt;&lt;/r:grant&gt;&lt;r:issuer&gt;&lt;Signature
xmlns=""http://www.w3.org/2000/09/xmldsig#""&gt;&lt;SignedInfo&gt;&lt;CanonicalizationMethod Algorithm=""http://www.microsoft.com/xrml/lwc14n""/&gt;&lt;SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1""/&gt;&lt;Reference&gt;&lt;Transforms&gt;&lt;Transform Algorithm=""urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform""/&gt;&lt;Transform Algorithm=""http://www.microsoft.com/xrml/lwc14n""/&gt;&lt;/Transforms&gt;&lt;DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""/&gt;&lt;DigestValue&gt;QKe+dFvsfVmEalzn7O/tEYua/sA=&lt;/DigestValue&gt;&lt;/Reference&gt;&lt;/SignedInfo&gt;&lt;SignatureValue&gt;GQImvPL+X4uXph5Uwf08oQ1RoJcveZyWwBhAP6Ob0yQdZCHfBk8CB0TBLzJ/J9zNcs9diyrY/2Pdv5igHiEd7j9bjDFIgqZXDeASCONaE/+LzjyOVhV6C8s7m0+0bVCsOXBGWz4mQdR69Svr9DmfhOjgrPi1vbcge9VyTYN2cpi6R3iNFi5HqaI0X8/35BfTyDciCRPR4G+ZysYte7Y+vvtjhm/PERmqFpt8nQZEbpxmib69T1eOYpttvS6a2zV4CmR+bH1kaBZWuKQrfAsfebOgxo09lTeFIddq/9d5Ggt8vwmh/HYF/UebSMCIZXgrLLZ0wUEIhfCKttbVmmSDtQ==&lt;/SignatureValue&gt;&lt;KeyInfo&gt;&lt;KeyValue&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;lAi6wXhcWOjn1rN1aIy6z4YBcYlkdrxP9EEw7iiD0tg6i0aVOgZ/FS6IxiOgZXYwTgK/BHA7QN6/lvxnecZ2cETT7w7ZRByGUN1zTQKFwXdyQz/xdp5kZ81bmI3EQWLJBT6iW5K8HZr0qRsQRlExUrWZSOI449+Br2QgOMcBMS3FEMBS8XCBPgZ3z/V9ydztWjhopBB0ZngebWEjqwtlrXEB1M+WOPWUcljdJlp5pXNkiqCrJEzenMJ+tfTfD/8zv08LdhhIAmx1VLViItRqO9OD7l313X7bVyfTWTxGmf7D9YS5Sa0UCiOXM0qVZCVuQ5CzjLRLa13FaJurQ6SBhQ==&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/KeyInfo&gt;&lt;/Signature&gt;&lt;r:details&gt;&lt;r:timeOfIssue&gt;2025-03-01T00:17:10Z&lt;/r:timeOfIssue&gt;&lt;/r:details&gt;&lt;/r:issuer&gt;&lt;r:otherInfo
xmlns:r=""urn:mpeg:mpeg21:2003:01-REL-R-NS""&gt;&lt;tm:infoTables
xmlns:tm=""http://www.microsoft.com/DRM/XrML2/TM/v2""&gt;&lt;tm:infoList tag=""#global""&gt;&lt;tm:infoStr name=""licenseType""&gt;msft:sl/PL/GENERIC/PRIVATE&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""licenseVersion""&gt;2.0&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""licensorUrl""&gt;https://licensing.microsoft.com&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""licenseCategory""&gt;msft:sl/PL/GENERIC/PRIVATE&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""publicCertificateId""&gt;{94f767e4-6a67-4c92-9d5c-2949e6973a26}&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""clientIssuanceCertificateId""&gt;{CE939C0E-53F7-4011-A286-78B6975FA5F0}&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""hwid:ootGrace""&gt;3&lt;/tm:infoStr&gt;&lt;tm:infoStr name=""migratable""&gt;true&lt;/tm:infoStr&gt;&lt;/tm:infoList&gt;&lt;/tm:infoTables&gt;&lt;/r:otherInfo&gt;&lt;/r:license&gt;&lt;/rg:licenseGroup&gt;";
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
                                    <Value>{ProductKeyType}</Value>
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
    }
}