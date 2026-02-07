using MsKeyChecker;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace CreatXmlAct
{
    internal class Program
    {
        static void Main(string[] args)
        {
            try
            {
                // ===================== 步骤1：初始化配置 =====================
                Console.WriteLine("=== 初始化PKeyConfig配置 ===");
                // 读取pkeyconfig.xrm-ms文件（替换为你的文件路径）
                string pkcFilePath = @"pkeyconfig.xrm-ms"; // 绝对路径示例
                                                              // 或使用相对路径（文件放在项目bin/Debug/net48目录下）
                                                              // string pkcFilePath = "pkeyconfig.xrm-ms";

                XDocument pkcXml = Utils.ReadXmlFile(pkcFilePath);
                PKeyConfig pkc = new PKeyConfig(pkcXml);
                Console.WriteLine("PKeyConfig配置加载成功！");

                // ===================== 步骤2：创建KeyChecker实例 =====================
                Console.WriteLine("\n=== 创建KeyChecker实例 ===");
                using (KeyChecker checker = new KeyChecker(pkc))
                {
                    // ===================== 示例1：单密钥验证 =====================
                    Console.WriteLine("\n=== 单密钥验证测试 ===");
                    string testKey = "MT6QD-N6YPG-K7CG9-TCYFJ-HMH26"; // 替换为实际密钥
                    KeyResult queryResult = checker.QueryKey(testKey);

                    // 输出验证结果
                    Console.WriteLine($"密钥：{testKey}");
                    Console.WriteLine($"验证状态：{(queryResult.Success ? "有效" : "无效")}");
                    if (!queryResult.Success)
                    {
                        Console.WriteLine($"错误码：{queryResult.HResult}");
                        Console.WriteLine($"错误信息：{queryResult.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                // 全局异常捕获
                Console.WriteLine($"程序执行出错：{ex.Message}");
                Console.WriteLine($"异常详情：{ex.StackTrace}");
            }

            Console.WriteLine("\n按任意键退出...");
            Console.ReadKey();
        }
    }
}
