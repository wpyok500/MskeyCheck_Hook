using System;
using System.Xml.Serialization;

[XmlRoot("ProductKeyConfiguration", Namespace = "http://www.microsoft.com/DRM/PKEY/Configuration/2.0")]
public class ProductKeyConfiguration
{
    [XmlArray("Configurations"), XmlArrayItem("Configuration")]
    public Configuration[] Configurations { get; set; }

    [XmlArray("KeyRanges"), XmlArrayItem("KeyRange")]
    public KeyRange[] KeyRanges { get; set; }

    [XmlArray("PublicKeys"), XmlArrayItem("PublicKey")]
    public PublicKey[] PublicKeys { get; set; }
}

public class Configuration
{
    [XmlElement("ActConfigId")]
    public string ActConfigId { get; set; }

    [XmlElement("RefGroupId")]
    public uint RefGroupId { get; set; }  // 改为 uint 更合适

    [XmlElement("EditionId")]
    public string EditionId { get; set; }

    [XmlElement("ProductDescription")]
    public string ProductDescription { get; set; }

    [XmlElement("ProductKeyType")]
    public string ProductKeyType { get; set; }

    [XmlElement("IsRandomized")]
    public bool IsRandomized { get; set; }
}

public class KeyRange
{
    [XmlElement("RefActConfigId")]
    public string RefActConfigId { get; set; }

    [XmlElement("PartNumber")]
    public string PartNumber { get; set; }

    [XmlElement("EulaType")]
    public string EulaType { get; set; }

    [XmlElement("IsValid")]
    public bool IsValid { get; set; }

    [XmlElement("Start")]
    public long Start { get; set; }  // 数字大，用 long

    [XmlElement("End")]
    public long End { get; set; }
}

public class PublicKey
{
    [XmlElement("GroupId")]
    public uint GroupId { get; set; }  // 改为 uint

    [XmlElement("AlgorithmId")]
    public string AlgorithmId { get; set; }

    [XmlElement("PublicKeyValue")]
    public string PublicKeyValue { get; set; }
}