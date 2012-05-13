using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;
using System.Xml;
using System.IO;

namespace ConsoleApplication31
{
    class Program
    {
        static void Main(string[] args)
        {
            var c = new XmlDsigExcC14NTransform(true, "");
            var doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.LoadXml("<root xmlns=\"ns1\"><child xmlns=\"ns2\"><inner xmlns=\"ns2\">123</inner></child></root>");
            var node = doc.SelectSingleNode("//*[local-name(.)='child']");
            var nodes = node.SelectNodes(".|.//*|.//text()|.//@*");
            c.LoadInput(nodes);
            
            //var h = new SHA1CryptoServiceProvider();
            //var b = c.GetDigestedOutput(h);
            //var b64 = Convert.ToBase64String(b);

            var res = c.GetOutput() as MemoryStream;
            string s2 = System.Text.Encoding.UTF8.GetString(res.ToArray());            
        }
    }
}
