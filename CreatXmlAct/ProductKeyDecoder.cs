using System;
using System.Collections.Generic;
using System.Numerics;

public class ProductKeyDecoder
{
    public const string ALPHABET = "BCDFGHJKMPQRTVWXY2346789";

    // 静态查找表：将字符直接映射到数值，避免 IndexOf 的 O(n) 搜索
    private static readonly sbyte[] CharTable = new sbyte[128];
    static ProductKeyDecoder()
    {
        for (int i = 0; i < 128; i++) CharTable[i] = -1;
        for (int i = 0; i < ALPHABET.Length; i++) CharTable[ALPHABET[i]] = (sbyte)i;
    }

    public BigInteger Key { get; }
    public long Group { get; }
    public long Serial { get; }
    public BigInteger Security { get; }
    public int Upgrade { get; }

    public ProductKeyDecoder(string key)
    {
        Key = Decode5x5(key);

        // 位域解析（严格遵循 20, 30, 53, 1 的分布）
        Group = (long)(Key & 0xFFFFF); // 20 bits
        Serial = (long)((Key >> 20) & 0x3FFFFFFF); // 30 bits
        Security = (Key >> 50) & ((BigInteger.One << 53) - 1); // 53 bits
        Upgrade = (int)((Key >> 103) & 1); // 1 bit
    }

    public static BigInteger Decode5x5(string key)
    {
        string normalized = key.Replace("-", "").ToUpper();
        if (normalized.Length != 25) throw new FormatException("Key must be 25 characters.");

        // 必须严格保持顺序：N 对应的值作为第一个被计算的元素
        int nIndex = normalized.IndexOf('N');
        string dataPart = normalized.Replace("N", "");

        BigInteger result = (BigInteger)nIndex; // N 的位置先入栈

        foreach (char c in dataPart)
        {
            sbyte val = (c < 128) ? CharTable[c] : (sbyte)-1;
            if (val == -1) throw new FormatException($"Invalid character: {c}");

            // 核心算法：result = result * 24 + value
            result = BigInteger.Add(BigInteger.Multiply(result, 24), (int)val);
        }

        return result;
    }

    public static string EncodeKeyData(long group, long serial, BigInteger security, int upgrade)
    {
        // 严格按照你原始逻辑中的位移重新拼装
        // 1 (upgrade) | 30 (serial) | 20 (group) | 53 (security)
        BigInteger actHash = (BigInteger)(upgrade & 1);
        actHash |= (BigInteger)(serial & 0x3FFFFFFF) << 1;
        actHash |= (BigInteger)(group & 0xFFFFF) << 31;
        actHash |= (security & ((BigInteger.One << 53) - 1)) << 51;

        byte[] bytes = actHash.ToByteArray();

        // 修正：确保输出固定为 13 字节，且不丢失数据
        byte[] result = new byte[13];
        int copyLen = Math.Min(bytes.Length, 13);
        Array.Copy(bytes, result, copyLen);

        return Convert.ToBase64String(result);
    }
}

public class ProductKeyDecoder2
{
    public const string ALPHABET = "BCDFGHJKMPQRTVWXY2346789";

    public BigInteger Key { get; }
    public BigInteger Group { get; }
    public BigInteger Serial { get; }
    public BigInteger Security { get; }
    public BigInteger Upgrade { get; }

    public ProductKeyDecoder2(string key)
    {
        Key = Decode5x5(key, ALPHABET);

        // 位域解析（实测正确）
        Group = Key & ((BigInteger.One << 20) - 1);
        Serial = (Key >> 20) & ((BigInteger.One << 30) - 1);
        Security = (Key >> 50) & ((BigInteger.One << 53) - 1);
        Upgrade = (Key >> 103) & 1;
    }

    /// <summary>
    /// 修复后的5x5密钥解码逻辑（符合微软原版算法）
    /// </summary>
    public static BigInteger Decode5x5(string key, string alphabet)
    {
        key = key.Replace("-", "");

        var dec = new List<int> { key.IndexOf('N') };
        foreach (var l in key.Replace("N", ""))
        {
            dec.Add(alphabet.IndexOf(l));
        }

        BigInteger result = 0;
        foreach (var x in dec)
        {
            result = (result * 24) + x;
        }
        return result;
    }

    /// <summary>
    /// 修复后的密钥数据编码逻辑（修正字节序）
    /// </summary>
    public static string EncodeKeyData(BigInteger group, BigInteger serial, BigInteger security, BigInteger upgrade)
    {
        BigInteger actHash = upgrade & 1;
        actHash |= (serial & ((1UL << 30) - 1)) << 1;
        actHash |= (group & ((1UL << 20) - 1)) << 31;
        actHash |= (security & ((1UL << 53) - 1)) << 51;

        byte[] bytes = actHash.ToByteArray();
        Array.Resize(ref bytes, 13);
        return Convert.ToBase64String(bytes);
    }
}


public class ProductKeyDecoder3
{
    public const string ALPHABET = "BCDFGHJKMPQRTVWXY2346789";

    private static readonly sbyte[] CharTable = new sbyte[128];
    static ProductKeyDecoder3()
    {
        // 修复：手动循环初始化，兼容所有 .NET 版本
        for (int i = 0; i < CharTable.Length; i++)
        {
            CharTable[i] = -1;
        }

        for (int i = 0; i < ALPHABET.Length; i++)
        {
            CharTable[ALPHABET[i]] = (sbyte)i;
        }
    }

    public BigInteger Key { get; }
    public int Group { get; }
    public int Serial { get; }
    public BigInteger Security { get; }
    public int Upgrade { get; }

    public ProductKeyDecoder3(string key)
    {
        if (string.IsNullOrEmpty(key)) throw new ArgumentNullException(nameof(key));

        Key = Decode5x5(key);

        // 位域解析
        Group = (int)(Key & 0xFFFFF);
        Serial = (int)((Key >> 20) & 0x3FFFFFFF);
        Security = (Key >> 50) & ((BigInteger.One << 53) - 1);
        Upgrade = (int)((Key >> 103) & 1);
    }

    public static BigInteger Decode5x5(string key)
    {
        // 兼容性优化：老版本 .NET 不支持 AsSpan，使用普通的字符串操作
        string normalized = key.Replace("-", "").ToUpper();
        if (normalized.Length != 25) throw new FormatException("密钥长度必须为 25 位");

        int nIndex = normalized.IndexOf('N');
        // 如果有 N，移除它以进行 Base24 转换
        string dataPart = nIndex != -1 ? normalized.Replace("N", "") : normalized;

        // N 的位置作为高位权重初始化
        BigInteger result = nIndex != -1 ? (BigInteger)nIndex : BigInteger.Zero;

        foreach (char c in dataPart)
        {
            sbyte val = (c < 128) ? CharTable[c] : (sbyte)-1;
            if (val == -1) throw new FormatException($"密钥包含非法字符: {c}");

            result = result * 24 + val;
        }

        return result;
    }

    public static string EncodeKeyData(int group, int serial, BigInteger security, int upgrade)
    {
        BigInteger actHash = (BigInteger)(upgrade & 1);
        actHash |= (BigInteger)(serial & 0x3FFFFFFF) << 1;
        actHash |= (BigInteger)(group & 0xFFFFF) << 31;
        actHash |= (security & ((BigInteger.One << 53) - 1)) << 51;

        byte[] rawBytes = actHash.ToByteArray();

        // 确保输出 13 字节缓冲区
        byte[] fixedBuffer = new byte[13];
        int bytesToCopy = Math.Min(rawBytes.Length, 13);
        Array.Copy(rawBytes, 0, fixedBuffer, 0, bytesToCopy);

        return Convert.ToBase64String(fixedBuffer);
    }
}

class Program
{
    static void Main1()
    {
        string key = "MT6QD-N6YPG-K7CG9-TCYFJ-HMH26";
        var d = new ProductKeyDecoder(key);
        Console.WriteLine("Key:      " + d.Key);
        Console.WriteLine("Group:    " + d.Group);    // 正确输出3308
        Console.WriteLine("Serial:   " + d.Serial);
        Console.WriteLine("Security: " + d.Security);
        Console.WriteLine("Upgrade:  " + d.Upgrade);
        string strbase64 = ProductKeyDecoder.EncodeKeyData(d.Group, d.Serial, d.Security, d.Upgrade);
        Console.WriteLine("Base64:   " + strbase64); // 正确输出hHe2EXYGGMG+BH8FWw==

        //=============================
        var d2 = new ProductKeyDecoder2(key);
        Console.WriteLine("Key:      " + d2.Key);
        Console.WriteLine("Group:    " + d2.Group);    // 正确输出3308
        Console.WriteLine("Serial:   " + d2.Serial);
        Console.WriteLine("Security: " + d2.Security);
        Console.WriteLine("Upgrade:  " + d2.Upgrade);
        string strbase64_2 = ProductKeyDecoder2.EncodeKeyData(d2.Group, d2.Serial, d2.Security, d2.Upgrade);
        Console.WriteLine("Base64:   " + strbase64_2); // 正确输出hHe2EXYGGMG+BH8FWw==
        //==============================

        var d3 = new ProductKeyDecoder3(key);
        Console.WriteLine("Key:      " + d3.Key);
        Console.WriteLine("Group:    " + d3.Group);    // 正确输出3308
        Console.WriteLine("Serial:   " + d3.Serial);
        Console.WriteLine("Security: " + d3.Security);
        Console.WriteLine("Upgrade:  " + d3.Upgrade);

        string strbase64_3 = ProductKeyDecoder3.EncodeKeyData(d3.Group, d3.Serial, d3.Security, d3.Upgrade);
        Console.WriteLine("Base64:   " + strbase64_3); // 正确输出hHe2EXYGGMG+BH8FWw==
        Console.ReadKey();
    }
}