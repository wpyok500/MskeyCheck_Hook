using System;
using System.Threading.Tasks;
using 密钥检测关键字符串Hook;
using GenerateXML;
using KeyCheck;

class Program
{
    static async Task Main(string[] args)
    {
        //var service = new ProductKeyHookServiceAsync(
        //    "pkeyconfig-office24_1.xrm-ms",
        //    "R98TR-69NMX-DKJFP-FXJC9-4JWCX"
        //);

        //var service = new ProductKeyHookServiceAsync(
        //    "pkconfig_winNext.xrm-ms",
        //    "VK7JG-NPHTM-C97JM-9MPGT-3V66T"
        //);

        //KeyHookResult result = await service.RunAsync();

        KeyHookResult result =  RunMain.RunC("VK7JG-NPHTM-C97JM-9MPGT-3V66T", "pkconfig_winNext.xrm-ms");

        // ==============================================
        // 这里是调用者完全控制展示，所有信息都齐全
        // ==============================================
        Console.WriteLine("===== 密钥检测完整结果 =====");
        Console.WriteLine($"ESI捕获: {result.ActConfigID}");
        Console.WriteLine($"密钥: {result.ProductKey}");
        Console.WriteLine($"Full ID: {result.PID}");
        Console.WriteLine($"Edition: {result.EditionShort}");
        Console.WriteLine($"PID: {result.PIDALL}");
        Console.WriteLine($"Internal Version(aid): {result.InternalVersionAid}");
        Console.WriteLine($"Edition: {result.EditionName}");
        Console.WriteLine($"Channel: {result.Channel}");
        Console.WriteLine($"Type: {result.KeyType}");
        Console.WriteLine($"Description: {result.ProductDescription}");
        Console.WriteLine($"Count: {result.KeyCount}");

        if (result.XmlResult != null)
        {
            Console.WriteLine("\n===== XML 激活结果 =====");
            Console.WriteLine($"HResult: {result.XmlResult.HResult}");
            Console.WriteLine($"Message: {result.XmlResult.Message}");
        }

        Console.WriteLine("\n===== 日志 =====");
        foreach (var log in result.Logs)
            Console.WriteLine(log);
        Console.ReadLine();
    }
}