using System.Collections.Generic;

public class KeyHookResult
{
    // 执行状态
    public string ProductKey { get; set; }
    public bool Success { get; set; }
    public int PidGenXReturnCode { get; set; }
    public string ExceptionMessage { get; set; }
    public List<string> Logs { get; set; } = new List<string>();

    // Hook 捕获
    public string ActConfigID { get; set; } = string.Empty;

    // DigitalProductID 解析
    public string PID { get; set; } = string.Empty;
    public string EditionShort { get; set; } = string.Empty; // 如 X23-57900

    // DigitalProductID4 解析
    public string PIDALL { get; set; } = string.Empty;
    public string InternalVersionAid { get; set; } = string.Empty;
    public string EditionName { get; set; } = string.Empty; // VisioPro2024Volume
    public string Channel { get; set; } = string.Empty; // Volume:MAK
    public string KeyType { get; set; } = string.Empty; // ltMAK
    public string ProductDescription { get; set; } = string.Empty;
    public int KeyCount { get; set; }

    // XML 请求结果
    public KeyResult XmlResult { get; set; }
}