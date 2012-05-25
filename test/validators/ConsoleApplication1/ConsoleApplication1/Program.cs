using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ConsoleApplication1
{
    class Program
    {
        static void Main(string[] args)
        {
            ServiceReference1.SimpleServiceSoapClient c = new ServiceReference1.SimpleServiceSoapClient();
            
            c.ClientCredentials.ServiceCertificate.DefaultCertificate
        }
    }
}
