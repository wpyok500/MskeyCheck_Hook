using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PidKeyPlugIn
{
    // Token: 0x0200001F RID: 31
    public class DecodeKeyData
    {
        // Token: 0x06000084 RID: 132 RVA: 0x00059960 File Offset: 0x00057B60
        public static string GetKeyData(string productKey, int status = 0)
        {
            bool flag = true;
            byte[] array2 = DecodeKeyData.GetKeyArray(productKey, ref flag);
            array2 = DecodeKeyData.GetEncryptArray(array2, flag);
            byte[] hashValue = DecodeKeyData.GetHashValue(array2);
            byte[] array3 = hashValue.Skip(16).Take(8).ToArray<byte>();
            bool flag4 = array3.SequenceEqual(new byte[8]);
            array2 = DecodeKeyData.GetActPkeyConfig(hashValue);
            bool flag7 = array2.SequenceEqual(new byte[13]);
            string text6 = Convert.ToBase64String(array2);
            return text6;
        }

       
        // Token: 0x06000088 RID: 136 RVA: 0x0005A8A4 File Offset: 0x00058AA4
        private static byte[] GetKeyArray(string productKey, ref bool flag)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(productKey);
            byte[] array = new byte[25];
            bool flag2 = false;
            bool flag3 = false;
            int i = 0;
            int num = 0;
            int num2 = 0;
            int num3 = 0;
            while (i < 25)
            {
                byte b = bytes[num];
                bool flag4 = b == 78 || b == 110;
                if (flag4)
                {
                    bool flag5 = flag3 || i >= 24;
                    if (flag5)
                    {
                        break;
                    }
                    flag2 = true;
                    array = BitConverter.GetBytes(i).Take(1).ToArray<byte>()
                        .Concat(array.Take(array.Length - 1).ToArray<byte>())
                        .ToArray<byte>();
                    i++;
                    num2 = num3;
                }
                else
                {
                    byte b2 = DecodeKeyData.pickStr(b);
                    bool flag6 = b2 < 24;
                    if (flag6)
                    {
                        array[i] = b2;
                        i++;
                    }
                    else
                    {
                        bool flag7 = b2 != 24 || (num != 5 && num != 11 && num != 17 && num != 23) || num2 >= 4;
                        if (flag7)
                        {
                            break;
                        }
                        num2 = (num3 = num2 + 1);
                    }
                }
                bool flag8 = ++num >= 29;
                if (flag8)
                {
                    bool flag9 = num2 == 4 && i == 25;
                    if (flag9)
                    {
                        flag = flag2;
                        return array;
                    }
                    break;
                }
                else
                {
                    flag3 = flag2;
                }
            }
            return array;
        }

        // Token: 0x06000089 RID: 137 RVA: 0x0005A9FC File Offset: 0x00058BFC
        private static byte pickStr(byte str)
        {
            byte b = 0;
            switch (str)
            {
                case 45:
                    b = 24;
                    break;
                case 46:
                case 47:
                case 48:
                case 49:
                case 53:
                case 58:
                case 59:
                case 60:
                case 61:
                case 62:
                case 63:
                case 64:
                case 65:
                case 69:
                case 73:
                case 76:
                case 78:
                case 79:
                case 83:
                case 85:
                case 90:
                case 91:
                case 92:
                case 93:
                case 94:
                case 95:
                case 96:
                case 97:
                case 101:
                case 105:
                case 108:
                case 110:
                case 111:
                case 115:
                case 117:
                    b = 25;
                    break;
                case 50:
                    b = 17;
                    break;
                case 51:
                    b = 18;
                    break;
                case 52:
                    b = 19;
                    break;
                case 54:
                    b = 20;
                    break;
                case 55:
                    b = 21;
                    break;
                case 56:
                    b = 22;
                    break;
                case 57:
                    b = 23;
                    break;
                case 66:
                case 98:
                    b = 0;
                    break;
                case 67:
                case 99:
                    b = 1;
                    break;
                case 68:
                case 100:
                    b = 2;
                    break;
                case 70:
                case 102:
                    b = 3;
                    break;
                case 71:
                case 103:
                    b = 4;
                    break;
                case 72:
                case 104:
                    b = 5;
                    break;
                case 74:
                case 106:
                    b = 6;
                    break;
                case 75:
                case 107:
                    b = 7;
                    break;
                case 77:
                case 109:
                    b = 8;
                    break;
                case 80:
                case 112:
                    b = 9;
                    break;
                case 81:
                case 113:
                    b = 10;
                    break;
                case 82:
                case 114:
                    b = 11;
                    break;
                case 84:
                case 116:
                    b = 12;
                    break;
                case 86:
                case 118:
                    b = 13;
                    break;
                case 87:
                case 119:
                    b = 14;
                    break;
                case 88:
                case 120:
                    b = 15;
                    break;
                case 89:
                case 121:
                    b = 16;
                    break;
            }
            return b;
        }

        // Token: 0x0600008A RID: 138 RVA: 0x0005ABD0 File Offset: 0x00058DD0
        private static byte[] GetEncryptArray(byte[] Src, bool flag)
        {
            int num = 0;
            int num2 = 0;
            byte[] array = new byte[16];
            do
            {
                byte b = Src[num];
                int num3 = 0;
                bool flag2 = num2 != 0;
                if (flag2)
                {
                    do
                    {
                        uint num4 = (uint)(24 * array[num3] + b);
                        array[num3] = (byte)num4;
                        b = (byte)(num4 >> 8);
                        num3++;
                    }
                    while (num3 < num2);
                }
                bool flag3 = b > 0;
                if (flag3)
                {
                    bool flag4 = num2 >= 16;
                    if (flag4)
                    {
                        break;
                    }
                    array[num2++] = b;
                }
                num++;
            }
            while (num < 25);
            if (flag)
            {
                byte[] array2 = array;
                int num5 = 14;
                array2[num5] |= 8;
            }
            return array;
        }

        // Token: 0x0600008B RID: 139 RVA: 0x0005AC84 File Offset: 0x00058E84
        private static byte[] GetHashValue(byte[] Src)
        {
            byte[] array = Src.Skip(12).Take(4).ToArray<byte>();
            int num = BitConverter.ToInt32(array, 0);
            num >>= 16;
            num = (((((num >> 3) & 1) << 2) ^ num) & 8) ^ num;
            num &= 254;
            Src[14] = (byte)num;
            Src[13] = 0;
            Src[12] = (byte)(array[0] & 127);
            byte b = (byte)((int)(2 * (array[1] & 127)) | (array[0] >> 7));
            int num2 = (array[2] >> 3) & 1;
            int num3 = (int)array[2] ^ (((int)array[2] ^ (4 * ((num2 != 0) ? num2 : 0))) & 8);
            byte b2 = (byte)(((2 * num3) | (array[1] >> 7)) & 3);
            int num4 = (int)DecodeKeyData.ToShort(b2, b);
            uint num5 = uint.MaxValue;
            int num6 = 0;
            int num7 = Src.Length;
            do
            {
                num5 = DecodeKeyData.hashData[(int)((uint)Src[num6++] ^ (num5 >> 24))] ^ (num5 << 8);
                num7--;
            }
            while (num7 > 0);
            byte[] array2 = new byte[32];
            num5 = ~num5 & 1023U;
            bool flag = (long)num4 == (long)((ulong)num5);
            if (flag)
            {
                array2[0] = Src[0];
                array2[1] = Src[1];
                int num8 = 0;
                byte[] array3 = array2;
                int num9 = 2;
                array3[num9] ^= (byte)((array2[2] ^ Src[2]) & 15);
                int num10 = 0;
                do
                {
                    array2[num10 + 4] = (byte)(((int)Src[3 + num10] << 4) | (Src[2 + num10] >> 4));
                    num10++;
                }
                while (num10 < 3);
                byte[] array4 = array2;
                int num11 = 7;
                array4[num11] ^= (byte)(((((int)Src[num10 + 3] << 4) | (Src[num10 + 2] >> 4)) ^ (int)array2[7]) & 63);
                do
                {
                    array2[num8 + 16] = (byte)(((int)Src[7 + num8] << 6) | (Src[6 + num8] >> 2));
                    num8++;
                }
                while (num8 < 6);
                byte[] array5 = array2;
                int num12 = 22;
                array5[num12] ^= (byte)(((int)array2[22] ^ (Src[12] >> 2)) & 31);
                byte[] array6 = array2;
                int num13 = 8;
                array6[num13] ^= (byte)(((int)array2[8] ^ (num3 >> 1)) & 1);
            }
            return array2;
        }

        // Token: 0x0600008C RID: 140 RVA: 0x0005AE74 File Offset: 0x00059074
        private static byte[] GetActPkeyConfig(byte[] Src)
        {
            byte[] array = new byte[256];
            int num = 0;
            array[0] = (byte)((Src[8] != 0) ? Src[8] : 0);
            array[1] = 0;
            array[5] = 0;
            do
            {
                byte b = Src[4 + num];
                byte b2 = (byte)(array[num + 1] & 254);
                array[num] = (byte)((array[num] & 1) | (2 * Src[4 + num]));
                num++;
                array[num] = (byte)((int)b2 | (b >> 7));
            }
            while (num < 3);
            int num2 = 0;
            byte[] array2 = array;
            int num3 = 3;
            array2[num3] ^= (byte)(((Src[7] * 2) ^ array[3]) & 126);
            do
            {
                byte b3 = (byte)(Src[num2] >> 1);
                byte b4 = (byte)(array[num2 + 4] & 128);
                array[num2 + 3] = (byte)(((int)Src[num2] << 7) | (int)(array[num2 + 3] & 127));
                num2++;
                array[num2 + 3] = (byte)(b3 | b4);
            }
            while (num2 < 2);
            int num4 = 0;
            int num5 = (int)(Src[2] & 15);
            array[5] = (byte)((num5 << 7) | (int)(array[5] & 127));
            array[6] = (byte)((num5 >> 1) | (int)(array[6] & 248));
            do
            {
                byte b5 = (byte)(Src[num4 + 16] >> 5);
                byte b6 = (byte)(array[num4 + 7] & 248);
                array[num4 + 6] = (byte)(((int)Src[num4 + 16] << 3) | (int)(array[num4 + 6] & 7));
                num4++;
                array[num4 + 6] = (byte)(b6 | b5);
            }
            while (num4 < 6);
            array[12] = (byte)((array[12] & 7) | (8 * Src[22]));
            byte[] array3 = array;
            array3[4] = array[4];
            array3[8] = array[8];
            array3[12] = array[12];
            return array3.Take(13).ToArray<byte>();
        }

        // Token: 0x0600008D RID: 141 RVA: 0x0005AFFC File Offset: 0x000591FC
        private static short ToShort(byte byte1, byte byte2)
        {
            return (short)(((int)byte1 << 8) | (int)byte2);
        }

        // Token: 0x04000093 RID: 147
        private static byte[] algorithm_2005 = new byte[]
        {
            149, 21, 115, 184, 246, 162, 11, 67, 167, 153,
            251, byte.MaxValue, 184, 26, 141, 115
        };

        // Token: 0x04000094 RID: 148
        private static byte[] algorithm_2009 = new byte[]
        {
            239, 114, 6, 102, 9, 120, 253, 76, 141, 84,
            65, 183, 251, 115, 137, 136
        };

        // Token: 0x04000095 RID: 149
        private static long[] hash1 = new long[] { 1711698671L, 1291679753L, 3074512013L, 2290709499L };

        // Token: 0x04000096 RID: 150
        private static uint[] hashData = new uint[]
        {
            0U, 79764919U, 159529838U, 222504665U, 319059676U, 398814059U, 445009330U, 507990021U, 638119352U, 583659535U,
            797628118U, 726387553U, 890018660U, 835552979U, 1015980042U, 944750013U, 1276238704U, 1221641927U, 1167319070U, 1095957929U,
            1595256236U, 1540665371U, 1452775106U, 1381403509U, 1780037320U, 1859660671U, 1671105958U, 1733955601U, 2031960084U, 2111593891U,
            1889500026U, 1952343757U, 2552477408U, 2632100695U, 2443283854U, 2506133561U, 2334638140U, 2414271883U, 2191915858U, 2254759653U,
            3190512472U, 3135915759U, 3081330742U, 3009969537U, 2905550212U, 2850959411U, 2762807018U, 2691435357U, 3560074640U, 3505614887U,
            3719321342U, 3648080713U, 3342211916U, 3287746299U, 3467911202U, 3396681109U, 4063920168U, 4143685023U, 4223187782U, 4286162673U,
            3779000052U, 3858754371U, 3904687514U, 3967668269U, 881225847U, 809987520U, 1023691545U, 969234094U, 662832811U, 591600412U,
            771767749U, 717299826U, 311336399U, 374308984U, 453813921U, 533576470U, 25881363U, 88864420U, 134795389U, 214552010U,
            2023205639U, 2086057648U, 1897238633U, 1976864222U, 1804852699U, 1867694188U, 1645340341U, 1724971778U, 1587496639U, 1516133128U,
            1461550545U, 1406951526U, 1302016099U, 1230646740U, 1142491917U, 1087903418U, 2896545431U, 2825181984U, 2770861561U, 2716262478U,
            3215044683U, 3143675388U, 3055782693U, 3001194130U, 2326604591U, 2389456536U, 2200899649U, 2280525302U, 2578013683U, 2640855108U,
            2418763421U, 2498394922U, 3769900519U, 3832873040U, 3912640137U, 3992402750U, 4088425275U, 4151408268U, 4197601365U, 4277358050U,
            3334271071U, 3263032808U, 3476998961U, 3422541446U, 3585640067U, 3514407732U, 3694837229U, 3640369242U, 1762451694U, 1842216281U,
            1619975040U, 1682949687U, 2047383090U, 2127137669U, 1938468188U, 2001449195U, 1325665622U, 1271206113U, 1183200824U, 1111960463U,
            1543535498U, 1489069629U, 1434599652U, 1363369299U, 622672798U, 568075817U, 748617968U, 677256519U, 907627842U, 853037301U,
            1067152940U, 995781531U, 51762726U, 131386257U, 177728840U, 240578815U, 269590778U, 349224269U, 429104020U, 491947555U,
            4046411278U, 4126034873U, 4172115296U, 4234965207U, 3794477266U, 3874110821U, 3953728444U, 4016571915U, 3609705398U, 3555108353U,
            3735388376U, 3664026991U, 3290680682U, 3236090077U, 3449943556U, 3378572211U, 3174993278U, 3120533705U, 3032266256U, 2961025959U,
            2923101090U, 2868635157U, 2813903052U, 2742672763U, 2604032198U, 2683796849U, 2461293480U, 2524268063U, 2284983834U, 2364738477U,
            2175806836U, 2238787779U, 1569362073U, 1498123566U, 1409854455U, 1355396672U, 1317987909U, 1246755826U, 1192025387U, 1137557660U,
            2072149281U, 2135122070U, 1912620623U, 1992383480U, 1753615357U, 1816598090U, 1627664531U, 1707420964U, 295390185U, 358241886U,
            404320391U, 483945776U, 43990325U, 106832002U, 186451547U, 266083308U, 932423249U, 861060070U, 1041341759U, 986742920U,
            613929101U, 542559546U, 756411363U, 701822548U, 3316196985U, 3244833742U, 3425377559U, 3370778784U, 3601682597U, 3530312978U,
            3744426955U, 3689838204U, 3819031489U, 3881883254U, 3928223919U, 4007849240U, 4037393693U, 4100235434U, 4180117107U, 4259748804U,
            2310601993U, 2373574846U, 2151335527U, 2231098320U, 2596047829U, 2659030626U, 2470359227U, 2550115596U, 2947551409U, 2876312838U,
            2788305887U, 2733848168U, 3165939309U, 3094707162U, 3040238851U, 2985771188U
        };
    }
}
