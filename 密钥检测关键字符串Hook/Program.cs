
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
        
        private static string ProductKeys = "F3RT8-NTK22-D4H84-T83DJ-D9MP6";
        static void Main(string[] args)
        {

            string actkey = PidKeyPlugIn.DecodeKeyData.GetKeyData(ProductKeys);
            Console.WriteLine(actkey);

            Console.ReadLine();
        }
        

    }

}