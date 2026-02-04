
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
        
        private static string ProductKeys = "HJX7N-DFKW9-GK3FQ-MPDY4-3DBP6";
        static void Main(string[] args)
        {

            string actkey = PidKeyPlugIn.DecodeKeyData.GetKeyData(ProductKeys);

            Console.ReadLine();
        }
        

    }

}