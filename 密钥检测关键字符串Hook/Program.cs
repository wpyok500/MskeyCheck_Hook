using System;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using EasyHook;

namespace 密钥检测关键字符串Hook
{
    internal class Program
    {
        #region ===== Native Delegates (严格匹配原生函数) =====
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int GetPID2Delegate(
            IntPtr fileTimePtr,
            IntPtr mpidPtr,
            int langId,
            int dwBuildNumber,
            int unkParam,
            IntPtr dpid2Ptr);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int FnPidGenX(
            string productKey,
            string pkeyPath,
            string mpcid,
            IntPtr unknown,
            IntPtr pid2,
            IntPtr pid3,
            IntPtr pid4);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int DelegateGetPKeyData(
            string productKey,
            string pkeyConfigPath,
            string mpcid,
            string algo,
            IntPtr oemId,
            IntPtr otherId,
            out string iid,
            out string description,
            out string channel,
            out string subType,
            StringBuilder pid);
        #endregion

        #region ===== Win32 API (带错误处理) =====
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        private static extern void RtlZeroMemory(IntPtr dst, int size);

        // 新增：设置DLL搜索路径（x86下路径问题更常见）
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetDllDirectory(string lpPathName);
        #endregion

        #region ===== Globals (线程安全/只读) =====
        private static LocalHook _hook;
        private static GetPID2Delegate _originalGetPID2;

        // 线程安全日志队列 + 退出信号
        private static readonly ConcurrentQueue<string> _logQueue = new ConcurrentQueue<string>();
        private static readonly ManualResetEvent _exitEvent = new ManualResetEvent(false);
        private static Thread _logThread; // 日志线程引用，便于等待退出

        // ⚠️ 修改1：替换为 x86 版本的 GetPID2 偏移（必须重新用IDA计算！）
        // 提示：x86 DLL 的偏移和 x64 完全不同，50073 是 x64 偏移，需替换
        private const long GET_PID2_OFFSET_X86 = 0; // 请用IDA计算x86 DLL的GetPID2 RVA偏移后填写
        private const string PRODUCT_KEY = "VK7JG-NPHTM-C97JM-9MPGT-3V66T";
        private const string CONFIG_FILE = "pkconfig_winNext.xrm-ms";
        #endregion

        static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("=== KeyHook Optimized (x86 / EasyHook) ===\n");

            // 修改2：环境校验改为仅支持 x86
            if (IntPtr.Size != 4) // x86下IntPtr.Size=4，x64=8
            {
                Console.WriteLine("❌ 仅支持 x86 进程，请修改项目编译配置");
                return;
            }

            // 资源声明（统一释放）
            IntPtr hDll = IntPtr.Zero;
            IntPtr p1 = IntPtr.Zero, p2 = IntPtr.Zero, p3 = IntPtr.Zero;

            try
            {
                // 新增：设置DLL搜索路径为当前目录（x86下必加，避免加载不到x86 DLL）
                SetDllDirectory(Environment.CurrentDirectory);

                // 配置文件校验
                string configPath = Path.Combine(Environment.CurrentDirectory, CONFIG_FILE);
                if (!File.Exists(configPath))
                    throw new FileNotFoundException("配置文件不存在", configPath);

                // 加载核心 DLL（x86版本的ProductKeyUtilities.dll）
                hDll = LoadLibrary("ProductKeyUtilities.dll");
                if (hDll == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "ProductKeyUtilities.dll (x86) 加载失败");

                // 安装 Hook
                InstallHook(hDll);

                // 分配非托管缓冲区
                (p1, p2, p3) = AllocateBuffers();

                // 启动异步日志线程
                StartLogWorker();

                // 解析产品密钥信息
                ParseProductKeyInfo(hDll, PRODUCT_KEY, configPath);

                // 调用 PidGenX 触发 Hook
                CallPidGenX(hDll, PRODUCT_KEY, configPath, p1, p2, p3);

                Console.WriteLine("\n✔ 执行完成，按回车退出...");
                Console.ReadLine();
                
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"❌ 执行异常：{ex}");
                Console.ResetColor();
            }
            finally
            {
                // 退出信号 + 等待日志线程输出剩余内容
                _exitEvent.Set();
                if (_logThread != null && _logThread.IsAlive)
                    _logThread.Join(1000); // 最多等待 1 秒

                // 资源清理
                Cleanup(hDll, p1, p2, p3);
            }
        }

        #region ===== Hook 核心逻辑 =====
        /// <summary>
        /// 安装 EasyHook（核心步骤）
        /// </summary>
        private static void InstallHook(IntPtr hModule)
        {
            // 修改3：使用 x86 偏移计算目标地址
            IntPtr targetAddr = new IntPtr(hModule.ToInt64() + GET_PID2_OFFSET_X86);
            Console.WriteLine($"🪝 准备 Hook GetPID2 @ 0x{targetAddr.ToInt64():X8}");

            // 创建 Hook（EasyHook 标准写法）
            _hook = LocalHook.Create(
                targetAddr,
                new GetPID2Delegate(Hook_GetPID2_Callback),
                null);

            // 启用 Hook：拦截所有线程
            _hook.ThreadACL.SetExclusiveACL(Array.Empty<int>());

            // 绑定原函数委托（绕过 Hook 调用原生函数）
            _originalGetPID2 = Marshal.GetDelegateForFunctionPointer<GetPID2Delegate>(targetAddr);

            Console.WriteLine($"✅ Hook 安装成功");
        }

        /// <summary>
        /// GetPID2 Hook 回调（异常隔离，绝不外泄）
        /// </summary>
        private static int Hook_GetPID2_Callback(
            IntPtr fileTimePtr,
            IntPtr mpidPtr,
            int langId,
            int dwBuildNumber,
            int unkParam,
            IntPtr dpid2Ptr)
        {
            try
            {
                // 记录拦截到的参数
                _logQueue.Enqueue($"[HOOK] GetPID2 被调用：LangId={langId}, BuildNumber={dwBuildNumber}, UnkParam={unkParam}");

                // 调用原生函数（核心：必须放行，否则业务中断）
                int retCode = _originalGetPID2(fileTimePtr, mpidPtr, langId, dwBuildNumber, unkParam, dpid2Ptr);

                // 解析返回结果（仅成功时解析）
                if (retCode == 0 && fileTimePtr != IntPtr.Zero)
                    ParseFileTimeStruct(fileTimePtr);

                return retCode;
            }
            catch (Exception ex)
            {
                // 异常隔离：Hook 回调绝对不能抛出异常
                _logQueue.Enqueue($"[HOOK] 回调异常：{ex.Message}");
                // 兜底调用原函数，保证业务不中断
                return _originalGetPID2(fileTimePtr, mpidPtr, langId, dwBuildNumber, unkParam, dpid2Ptr);
            }
        }
        #endregion

        #region ===== 工具方法（模块化） =====
        /// <summary>
        /// 解析 FileTime 结构体（修改4：适配x86内存布局）
        /// </summary>
        private static void ParseFileTimeStruct(IntPtr ptr)
        {
            try
            {
                // x86 下内存布局（指针占4字节）：
                // 前 4 字节 = index (int)，接下来 4 字节 = ActConfigKey 指针 (IntPtr)
                int index = Marshal.ReadInt32(ptr); // 读取index（x86/x64都一样，int占4字节）
                IntPtr keyPtr = Marshal.ReadIntPtr(ptr, 4); // x86下指针占4字节，偏移4字节正确

                // x86下字符串读取方式不变
                string actConfigKey = Marshal.PtrToStringUni(keyPtr);

                _logQueue.Enqueue($"[HOOK] FileTime 解析：Index={index}, ActConfigKey={actConfigKey ?? "空"}");
            }
            catch (Exception ex)
            {
                _logQueue.Enqueue($"[HOOK] FileTime 解析失败：{ex.Message}");
            }
        }

        /// <summary>
        /// 分配非托管缓冲区（初始化+防脏数据）
        /// </summary>
        private static (IntPtr, IntPtr, IntPtr) AllocateBuffers()
        {
            // 缓冲区大小 x86/x64 一致（字节数不随位数变）
            IntPtr buf1 = Marshal.AllocHGlobal(100);
            IntPtr buf2 = Marshal.AllocHGlobal(164);
            IntPtr buf3 = Marshal.AllocHGlobal(1272);

            // 内存置零，避免脏数据
            RtlZeroMemory(buf1, 100);
            RtlZeroMemory(buf2, 164);
            RtlZeroMemory(buf3, 1272);

            // 设置 DLL 要求的标志位（x86 DLL 标志位可能和x64一致，也可能不同，需验证）
            Marshal.WriteByte(buf1, 0, 50);
            Marshal.WriteByte(buf2, 0, 164);
            Marshal.WriteByte(buf3, 0, 248);
            Marshal.WriteByte(buf3, 1, 4);

            Console.WriteLine($"✅ 非托管缓冲区分配完成");
            return (buf1, buf2, buf3);
        }

        /// <summary>
        /// 解析产品密钥信息（扩展功能）
        /// </summary>
        private static void ParseProductKeyInfo(IntPtr hDll, string key, string configPath)
        {
            IntPtr funcPtr = GetProcAddress(hDll, "GetPKeyData");
            if (funcPtr == IntPtr.Zero)
            {
                _logQueue.Enqueue("[INFO] 未找到 GetPKeyData 函数，跳过密钥解析");
                return;
            }

            try
            {
                var getPKeyData = Marshal.GetDelegateForFunctionPointer<DelegateGetPKeyData>(funcPtr);
                StringBuilder pidSb = new StringBuilder(256);

                int ret = getPKeyData(
                    key, configPath, null, null,
                    IntPtr.Zero, IntPtr.Zero,
                    out string iid,
                    out string desc,
                    out string channel,
                    out string subType,
                    pidSb);

                _logQueue.Enqueue($"[INFO] 密钥解析：返回值={ret}, IID={iid ?? "空"}, 描述={desc ?? "空"}, 渠道={channel ?? "空"}, PID={pidSb}");
            }
            catch (Exception ex)
            {
                _logQueue.Enqueue($"[WARN] 密钥解析失败：{ex.Message}");
            }
        }

        /// <summary>
        /// 调用 PidGenX（触发 Hook）
        /// </summary>
        private static void CallPidGenX(IntPtr hDll, string key, string configPath, IntPtr p1, IntPtr p2, IntPtr p3)
        {
            IntPtr funcPtr = GetProcAddress(hDll, "PidGenX");
            if (funcPtr == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "未找到 PidGenX 函数");

            var pidGenX = Marshal.GetDelegateForFunctionPointer<FnPidGenX>(funcPtr);
            _logQueue.Enqueue("[INFO] 调用 PidGenX 函数（将触发 Hook）");

            int ret = pidGenX(key, configPath, "55041", IntPtr.Zero, p1, p2, p3);
            _logQueue.Enqueue($"[INFO] PidGenX 调用完成，返回值={ret} (0=成功)");
        }

        /// <summary>
        /// 启动异步日志线程（线程安全输出）
        /// </summary>
        private static void StartLogWorker()
        {
            _logThread = new Thread(() =>
            {
                while (!_exitEvent.WaitOne(50)) // 50ms 轮询一次
                {
                    while (_logQueue.TryDequeue(out string log))
                    {
                        Console.WriteLine(log);
                    }
                }

                // 退出前输出剩余日志
                while (_logQueue.TryDequeue(out string remainingLog))
                {
                    Console.WriteLine(remainingLog);
                }
            })
            {
                IsBackground = true,
                Name = "LogWorker"
            };

            _logThread.Start();
            Console.WriteLine($"✅ 日志线程启动成功");
        }

        /// <summary>
        /// 资源清理（统一释放，避免泄漏）
        /// </summary>
        private static void Cleanup(IntPtr hDll, params IntPtr[] buffers)
        {
            Console.WriteLine("\n🧹 开始清理资源...");

            // 释放 Hook
            if (_hook != null)
            {
                _hook.Dispose();
                _originalGetPID2 = null;
                Console.WriteLine($"✅ Hook 已释放");
            }

            // 释放非托管缓冲区
            foreach (var buf in buffers)
            {
                if (buf != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buf);
                }
            }
            Console.WriteLine($"✅ 非托管缓冲区已释放");

            // 释放 DLL
            if (hDll != IntPtr.Zero && FreeLibrary(hDll))
            {
                Console.WriteLine($"✅ ProductKeyUtilities.dll (x86) 已释放");
            }

            Console.WriteLine($"✅ 所有资源清理完成");
        }
        #endregion
    }
}