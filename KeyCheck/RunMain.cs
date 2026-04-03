using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace KeyCheck
{
    /// <summary>
    /// 主入口静态类
    /// 提供 C# 调用接口 + 易语言 DLL 导出接口
    /// 每次调用支持不同 key / pkeypath
    /// </summary>
    public static class RunMain
    {
        /// <summary>
        /// 线程安全锁，防止多线程下重复释放 DLL
        /// </summary>
        private static readonly object _lockObj = new object();

        /// <summary>
        /// 标记依赖 DLL 是否已释放
        /// </summary>
        private static bool _dllExtracted = false;

        /// <summary>
        /// 创建服务实例（每次调用都新建，适配不同 key/pkeypath）
        /// </summary>
        /// <param name="pkeypath">密钥文件路径</param>
        /// <param name="key">校验密钥</param>
        /// <returns>服务实例</returns>
        private static ProductKeyHookServiceAsync CreateHookService(string pkeypath, string key)
        {
            // 每次新建实例，确保每次传入的参数都生效
            return new ProductKeyHookServiceAsync(pkeypath, key);
        }

        /// <summary>
        /// 【C# 内部调用接口】
        /// 直接返回实体对象，适合 C# 项目引用使用
        /// </summary>
        /// <param name="key">密钥</param>
        /// <param name="pkeypath">密钥文件路径</param>
        /// <returns>KeyHookResult 实体结果</returns>
        public static KeyHookResult RunC(string key, string pkeypath)
        {
            try
            {
                // 确保嵌入的依赖 DLL 已释放到程序目录
                ExtractAllDlls();

                // 创建服务并同步执行异步逻辑
                var service = CreateHookService(pkeypath, key);
                return service.RunAsync().GetAwaiter().GetResult();
            }
            catch
            {
                // 异常返回失败结果
                return new KeyHookResult { Success = false, EMessageErr = "执行失败" };
            }
        }

        /// <summary>
        /// 【易语言导出接口】
        /// 调用约定：StdCall（易语言标准）
        /// 导出函数名：RunE
        /// </summary>
        /// <param name="key">密钥（ANSI 字符串）</param>
        /// <param name="pkeypath">密钥路径（ANSI 字符串）</param>
        /// <returns>JSON 字符串指针，必须调用 FreeMem 释放</returns>
        [DllExport("RunE", CallingConvention = CallingConvention.StdCall)]
        public static IntPtr RunE([MarshalAs(UnmanagedType.LPStr)] string key, [MarshalAs(UnmanagedType.LPStr)] string pkeypath)
        {
            try
            {
                // 确保依赖 DLL 已释放
                ExtractAllDlls();

                // 创建服务并执行
                var service = CreateHookService(pkeypath, key);
                KeyHookResult result = service.RunAsync().GetAwaiter().GetResult();

                // JSON 序列化（支持中文、压缩格式）
                string json = JsonSerializer.Serialize(result, new JsonSerializerOptions
                {
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                    WriteIndented = false
                });

                // 分配非托管内存返回给易语言
                return Marshal.StringToHGlobalAnsi(json);
            }
            catch (Exception ex)
            {
                // 异常时返回错误 JSON
                return Marshal.StringToHGlobalAnsi(JsonSerializer.Serialize(new KeyHookResult
                {
                    Success = false,
                    EMessageErr = "异常：" + ex.Message
                }));
            }
        }

        /// <summary>
        /// 【易语言必须调用】
        /// 释放 RunE 返回的字符串指针内存
        /// 防止内存泄漏
        /// </summary>
        /// <param name="ptr">内存指针</param>
        [DllExport("FreeMem", CallingConvention = CallingConvention.StdCall)]
        public static void FreeMem(IntPtr ptr)
        {
            if (ptr != IntPtr.Zero)
                Marshal.FreeHGlobal(ptr);
        }

        #region 🔥 自动释放所有依赖 DLL（一次释放，永不重复，兼容.NET 4.8）
        private static void ExtractAllDlls()
        {
            if (_dllExtracted)
                return;

            lock (_lockObj)
            {
                if (_dllExtracted)
                    return;

                string baseDir = AppDomain.CurrentDomain.BaseDirectory;

                // 待释放的DLL列表
                string[] dlls = new string[]
                {
                    "ProductKeyUtilities.dll",
                    "FASM.DLL",
                    "FASMX64.DLL"
                };

                foreach (string dll in dlls)
                {
                    try
                    {
                        string outputPath = Path.Combine(baseDir, dll);
                        if (File.Exists(outputPath))
                            continue;

                        // 自动匹配资源名（完美解决大小写/路径问题）
                        string resourceName = Array.Find(
                            typeof(RunMain).Assembly.GetManifestResourceNames(),
                            r => r.EndsWith("." + dll, StringComparison.OrdinalIgnoreCase)
                        );

                        if (string.IsNullOrEmpty(resourceName))
                        {
                            System.Diagnostics.Trace.WriteLine($"[ExtractDll] 未找到资源: {dll}");
                            continue;
                        }

                        // .NET 4.8 标准流操作，绝对稳定
                        Stream stream = typeof(RunMain).Assembly.GetManifestResourceStream(resourceName);
                        if (stream == null)
                            continue;

                        FileStream fs = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
                        stream.CopyTo(fs);

                        fs.Flush();
                        fs.Close();
                        stream.Close();

                        System.Diagnostics.Trace.WriteLine($"[ExtractDll] 成功释放: {dll} -> {outputPath}");
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Trace.WriteLine($"[ExtractDll] 释放失败: {dll}, 错误: {ex.Message}");
                    }
                }

                _dllExtracted = true;
            }
        }
        #endregion
    }
}