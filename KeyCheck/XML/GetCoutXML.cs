using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace GenerateXML
{
    /// <summary>
    /// 静态类，提供获取微软密钥剩余激活次数的功能
    /// </summary>
    public class GetCoutXML
    {
        private static readonly byte[] BPrivateKey = new byte[]
        {
            0xfe, 0x31, 0x98, 0x75, 0xfb, 0x48, 0x84, 0x86, 0x9c, 0xf3, 0xf1, 0xce, 0x99, 0xa8, 0x90, 0x64,
            0xab, 0x57, 0x1f, 0xca, 0x47, 0x04, 0x50, 0x58, 0x30, 0x24, 0xe2, 0x14, 0x62, 0x87, 0x79, 0xa0,
        };
        /// <summary>
        /// 
        /// </summary>
        /// <param name="fullpid">如55041-05031-684-173151-03-2052-9200.0000-0912026</param>
        /// <returns></returns>
        public static string GetCount(string fullpid)
        {
            // XML Namespace
            string uri = "http://www.microsoft.com/DRM/SL/BatchActivationRequest/1.0";

            // Create new XML Document
            XmlDocument xmlDoc = new XmlDocument();

            // Create Root Element
            XmlElement rootElement = xmlDoc.CreateElement("ActivationRequest", uri);
            xmlDoc.AppendChild(rootElement);

            // Create VersionNumber Element
            XmlElement versionNumber = xmlDoc.CreateElement("VersionNumber", rootElement.NamespaceURI);
            versionNumber.InnerText = "2.0";
            rootElement.AppendChild(versionNumber);

            // Create RequestType Element
            XmlElement requestType = xmlDoc.CreateElement("RequestType", rootElement.NamespaceURI);
            requestType.InnerText = "2";
            rootElement.AppendChild(requestType);

            // Create Requests Group Element
            XmlElement requestsGroupElement = xmlDoc.CreateElement("Requests", rootElement.NamespaceURI);

            // Add PID as Request Element
            XmlElement requestElement = xmlDoc.CreateElement("Request", requestsGroupElement.NamespaceURI);
            XmlElement pidEntry = xmlDoc.CreateElement("PID", requestElement.NamespaceURI);
            //pidEntry.InnerText = pid;

            pidEntry.InnerText = fullpid.Replace("XXXXX", "55041");
            requestElement.AppendChild(pidEntry);

            // Add Request Element to Requests Group Element
            requestsGroupElement.AppendChild(requestElement);

            // Add Requests and Request to XML Document
            rootElement.AppendChild(requestsGroupElement);

            // Get Unicode Byte Array of XML Document
            byte[] byteXML = Encoding.Unicode.GetBytes(xmlDoc.InnerXml);

            // Convert Byte Array to Base64
            string base64XML = Convert.ToBase64String(byteXML);

            // Compute Digest of the Base 64 XML Bytes
            HMACSHA256 hmacsha256 = new HMACSHA256
            {
                Key = BPrivateKey
            };
            string digest = Convert.ToBase64String(hmacsha256.ComputeHash(byteXML));

            string form = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><soap:Body><BatchActivate xmlns=\"http://www.microsoft.com/BatchActivationService\"><request><Digest>REPLACEME1</Digest><RequestXml>REPLACEME2</RequestXml></request></BatchActivate></soap:Body></soap:Envelope>";
            form = form.Replace("REPLACEME1", digest); //put your Digest value (BASE64 encoded)
            form = form.Replace("REPLACEME2", base64XML); //put your mystr (BASE64 encoded)

            /*
             * Now create a request with following Header:
             * POST https://activation.sls.microsoft.com/BatchActivation/BatchActivation.asmx HTTP/1.1
             * User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; MS Web Services Client Protocol 4.0.30319.1)
             * Content-Type: text/xml; charset=utf-8
             * SOAPAction: "http://www.microsoft.com/BatchActivationService/BatchActivate"
             * Host: activation.sls.microsoft.com
             * Content-Length: 1150
             * Expect: 100-continue
             * 
             * And post your 'form' value using HTTPS!
             * Then parse server response.
             */

            //return form;
            return GetMSKeyCount(form);
        }

        private static string GetMSKeyCount(string xmlform)
        {

            XmlDocument soapEnvelopeXml = new XmlDocument();
            soapEnvelopeXml.LoadXml(xmlform);

            // Create Web Request
            HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create("https://activation.sls.microsoft.com/BatchActivation/BatchActivation.asmx");
            webRequest.Method = "POST";
            webRequest.ContentType = "text/xml; charset=\"utf-8\"";
            webRequest.Headers.Add("SOAPAction", "http://www.microsoft.com/BatchActivationService/BatchActivate");
            webRequest.Host = "activation.sls.microsoft.com";

            // Insert SOAP Envelope into Web Request
            using (Stream stream = webRequest.GetRequestStream())
            {
                soapEnvelopeXml.Save(stream);
            }

            // Begin Async call to Web Request
            IAsyncResult asyncResult = webRequest.BeginGetResponse(null, null);

            // Suspend Thread until call is complete
            asyncResult.AsyncWaitHandle.WaitOne();

            // Get the Response from the completed Web Request
            string soapResult;
            using (WebResponse webResponse = webRequest.EndGetResponse(asyncResult))
            using (StreamReader rd = new StreamReader(webResponse.GetResponseStream()))
            {
                soapResult = rd.ReadToEnd();
            }

            // Parse the ResponseXML from the Response
            using (XmlReader soapReader = XmlReader.Create(new StringReader(soapResult)))
            {
                // Read ResponseXML Value
                soapReader.ReadToFollowing("ResponseXml");
                string responseXML = soapReader.ReadElementContentAsString();

                // Remove HTML Entities from ResponseXML
                responseXML = responseXML.Replace("&gt;", ">");
                responseXML = responseXML.Replace("&lt;", "<");

                // Change Encoding Value in ResponseXML
                responseXML = responseXML.Replace("utf-16", "utf-8");

                // Read Fixed ResponseXML Value as XML
                using (XmlReader reader = XmlReader.Create(new StringReader(responseXML)))
                {
                    reader.ReadToFollowing("ActivationRemaining");
                    string count = reader.ReadElementContentAsString();

                    if (Convert.ToInt32(count) < 0)
                    {
                        reader.ReadToFollowing("ErrorCode");
                        string error = reader.ReadElementContentAsString();

                        if (error == "0x67")
                        {
                            return "0 (Blocked)";
                        }
                    }
                    return count;
                }
            }
        }

        /// <summary>
        /// 获取密钥版本信息
        /// </summary>
        /// <param name="pkeyconfig"></param>
        /// <param name="aid">如 {4de7cb65-cdf1-4de9-8ae8-e3cce27b9f2c}</param>
        /// <param name="edi">如 Professiona</param>
        /// <returns></returns>
        static string GetProductDescription(string pkeyconfig, string aid, string edi)
        {
            XmlDocument doc = new XmlDocument();
            doc.Load(pkeyconfig);
            MemoryStream stream = new MemoryStream(Convert.FromBase64String(doc.GetElementsByTagName("tm:infoBin")[0].InnerText));
            doc.Load(stream);
            XmlNamespaceManager ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("pkc", "http://www.microsoft.com/DRM/PKEY/Configuration/2.0");
            try
            {
                XmlNode node = doc.SelectSingleNode("/pkc:ProductKeyConfiguration/pkc:Configurations/pkc:Configuration[pkc:ActConfigId='" + aid + "']", ns);
                if (node == null)
                {
                    node = doc.SelectSingleNode("/pkc:ProductKeyConfiguration/pkc:Configurations/pkc:Configuration[pkc:ActConfigId='" + aid.ToUpper() + "']", ns);
                }
                if (node.HasChildNodes)
                {
                    if (node.ChildNodes[2].InnerText.Contains(edi))
                    {
                        return node.ChildNodes[3].InnerText;
                    }
                    return "Not Found";
                }
                return "Not Found";
            }
            catch (Exception)
            {
                return "Not Found";
            }
            finally
            {
                stream.Dispose();
            }
        }

        static string GetCryptoID(string pkey, string aid)
        {
            XmlDocument doc = new XmlDocument();
            doc.Load(pkey);
            MemoryStream stream = new MemoryStream(Convert.FromBase64String(doc.GetElementsByTagName("tm:infoBin")[0].InnerText));
            doc.Load(stream);
            XmlNamespaceManager ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("pkc", "http://www.microsoft.com/DRM/PKEY/Configuration/2.0");
            try
            {
                XmlNode node = doc.SelectSingleNode("/pkc:ProductKeyConfiguration/pkc:Configurations/pkc:Configuration[pkc:ActConfigId='" + aid + "']", ns);
                if (node == null)
                {
                    node = doc.SelectSingleNode("/pkc:ProductKeyConfiguration/pkc:Configurations/pkc:Configuration[pkc:ActConfigId='" + aid.ToUpper() + "']", ns);
                }
                if (node.HasChildNodes)
                {
                    return node.ChildNodes[1].InnerText;
                }
                return "Not Found";
            }
            catch (Exception)
            {
                return "Not Found";
            }
            finally
            {
                stream.Dispose();
            }
        }
    }
}
