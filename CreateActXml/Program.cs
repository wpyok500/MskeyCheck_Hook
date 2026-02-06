using System;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace CreateActXml
{
    public class Program
    {
        static void Main(string[] args)
        {
            try
            {
                

                // 同步调用
                string productKey = "GC6HC-JQ8YG-8WY69-Y338J-GXWP3";
                string productDesc = "Windows 7 Professional OEM:COA"; 
                string configId = "msft2005:da22eadd-46dc-4056-a287-f5041c852470&ljvx1q8BAAAAAAAA";
                string hResult = ProductActivationApi.GetActivationHResult(productKey, productDesc, configId);
                Console.WriteLine("激活错误码：" + hResult);

                // 异步调用（推荐，非UI线程）
                var res = ProductActivationApi.GetActivationHResultAsync(productKey, productDesc, configId);
                res.Wait();
                var err = res.Result;
                Console.WriteLine("激活错误码（异步）：" + err);

                // 同步调用
                productKey = "MT6QD-N6YPG-K7CG9-TCYFJ-HMH26";
                productDesc = "Win 10 RTM Professional Retail"; // 产品描述：Win/Office/Win 10 RTM等
                configId = "msft2009:4de7cb65-cdf1-4de9-8ae8-e3cce27b9f2c&hHe2EXYGGMG+BH8FWw=="; // 2005/2009配置ID
                hResult = ProductActivationApi.GetActivationHResult(productKey, productDesc, configId);
                Console.WriteLine("激活错误码：" + hResult);

                // 异步调用（推荐，非UI线程）
                res = ProductActivationApi.GetActivationHResultAsync(productKey, productDesc, configId);
                res.Wait();
                err = res.Result;
                Console.WriteLine("激活错误码（异步）：" + err);

                productKey = "VQDFW-P9MF8-XXGWP-JKTC3-K3773";
                productDesc = "Windows 7 SP1 Professional Retail"; // 产品描述：Win/Office/Win 10 RTM等
                configId = "msft2005:c1e88de3-96c4-4563-ad7d-775f65b1e670&tOznU2ABAAAAAAAA"; // 2005/2009配置ID
                hResult = ProductActivationApi.GetActivationHResult(productKey, productDesc, configId);
                Console.WriteLine("激活错误码：" + hResult);

                // 异步调用（推荐，非UI线程）
                res = ProductActivationApi.GetActivationHResultAsync(productKey, productDesc, configId);
                res.Wait();
                err = res.Result;
                Console.WriteLine("激活错误码（异步）：" + err);
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