
using SppTokenGenerator;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace 密钥检测关键字符串Hook
{
    class Program
    {
        
        private static string ProductKeys2009 = "F3RT8-NTK22-D4H84-T83DJ-D9MP6"; //2009
        private static string ProductKeys2005 = "8XCXT-HWWHH-H77DW-3JXTB-6Q4TW"; //2009
        static void Main(string[] args)
        {

            string actkey2009 = PidKeyPlugIn.DecodeKeyData.GetKeyData2009(ProductKeys2009);
            Console.WriteLine("2009："+ actkey2009);

            //有问题待修正
            string actkey2005 = PidKeyPlugIn.DecodeKeyData.GetKeyData2005("2005：" + ProductKeys2005);
            Console.WriteLine(actkey2005);

            Console.ReadLine();
        }
        

    }

}