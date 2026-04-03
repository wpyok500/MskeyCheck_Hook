using System;
using System.IO;
using System.Reflection;
using System.Threading;

namespace KeyCheck
{
    /// <summary>
    /// 嵌入资源提取工具（线程安全，防重复释放）
    /// </summary>
    public static class ResourceExtractor
    {
        private static int _isExtracted = 0; // 0=未提取，1=已提取
        private static readonly object _lockObj = new object();

        /// <summary>
        /// 从嵌入资源提取DLL到程序根目录
        /// </summary>
        /// <param name="resourceName">嵌入资源名（格式：命名空间.文件名.dll）</param>
        /// <param name="outputFileName">输出文件名</param>
        /// <returns>是否成功提取</returns>
        public static bool ExtractDllFromResource(string resourceName, string outputFileName)
        {
            // 原子操作判断是否已提取，避免锁开销
            if (Interlocked.CompareExchange(ref _isExtracted, 1, 0) != 0)
                return true; // 已提取，直接返回

            try
            {
                lock (_lockObj)
                {
                    // 二次校验，防止多线程竞争
                    if (File.Exists(outputFileName))
                        return true;

                    // 从嵌入资源读取DLL
                    Assembly assembly = Assembly.GetExecutingAssembly();
                    using (Stream stream = assembly.GetManifestResourceStream(resourceName))
                    {
                        if (stream == null)
                            throw new FileNotFoundException($"嵌入资源 {resourceName} 未找到");

                        // 写入到程序根目录
                        using (FileStream fs = new FileStream(outputFileName, FileMode.Create, FileAccess.Write))
                        {
                            stream.CopyTo(fs);
                        }
                    }

                    return true;
                }
            }
            catch (Exception ex)
            {
                // 提取失败，重置状态，允许下次重试
                Interlocked.Exchange(ref _isExtracted, 0);
                throw new InvalidOperationException($"DLL释放失败: {ex.Message}", ex);
            }
        }
    }
}