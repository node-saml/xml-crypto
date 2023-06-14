using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.IO;

namespace ConsoleApplication31
{
    /*
    class Program
    {
        static void Main(string[] args)
        {
            GetCanonization();
            //GetSignature();

        }

        static void GetSignature()
        {
            XmlDocument doc = new XmlDocument();
            //doc.LoadXml("<root><x xmlns=\"ns\" Id=\"_0\"></x><y attr=\"value\" Id=\"_1\"></y><z><w Id=\"_2\"></w></z></root>");
            doc.LoadXml("<root><x xmlns=\"ns\" Id=\"_0\"></x><y attr=\"value\" Id=\"_1\"></y><z><w Id=\"_2\"></w></z></root>");
            SignedXml signedXml = new SignedXml(doc);

            var c = new X509Certificate2(
                File.ReadAllBytes(@"C:\Program Files\Microsoft WSE\v2.0\Samples\Sample Test Certificates\Client Private.pfx"), "wse2qs");

            signedXml.SigningKey = c.PrivateKey;
            signedXml.Signature.SignedInfo.CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";

            Reference ref0 = new Reference();
            ref0.Uri = "#_0";
            Reference ref1 = new Reference();
            ref1.Uri = "#_1";
            Reference ref2 = new Reference();
            ref2.Uri = "#_2";

            var t = new XmlDsigExcC14NTransform();
            ref0.AddTransform(t);
            ref1.AddTransform(t);
            ref2.AddTransform(t);

            signedXml.AddReference(ref0);
            signedXml.AddReference(ref1);
            signedXml.AddReference(ref2);

            signedXml.ComputeSignature();
            var xmlDigitalSignature = signedXml.GetXml();
            var s = xmlDigitalSignature.OuterXml;
        }

        static void GetCanonization()
        {
            var c = new XmlDsigExcC14NTransform(true, "");
            var doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.LoadXml("<x xmlns=\"ns\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"_0\"/>");
            var node = doc.SelectSingleNode("//*[local-name(.)='x']");
            var nodes = node.SelectNodes(".|.//*|.//text()|.//@*");
            c.LoadInput(nodes);

            var h = new SHA1CryptoServiceProvider();
            var b = c.GetDigestedOutput(h);
            var b64 = Convert.ToBase64String(b);

            var res = c.GetOutput() as MemoryStream;
            string s2 = System.Text.Encoding.UTF8.GetString(res.ToArray());
        }
    }*/
}
