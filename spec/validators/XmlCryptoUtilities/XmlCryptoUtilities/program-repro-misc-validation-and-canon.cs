//
// This example signs an XML file using an
// envelope signature. It then verifies the 
// signed XML.
//
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.IO;
using System.Reflection;

public class SignVerifyEnvelope
{
    public sealed class RSAPKCS1SHA256SignatureDescription : SignatureDescription
    {
        public RSAPKCS1SHA256SignatureDescription()
        {
            base.KeyAlgorithm = typeof(RSACryptoServiceProvider).FullName;
            base.DigestAlgorithm = typeof(SHA256Managed).FullName;
            base.FormatterAlgorithm = typeof(RSAPKCS1SignatureFormatter).FullName;
            base.DeformatterAlgorithm = typeof(RSAPKCS1SignatureDeformatter).FullName;
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }

            RSAPKCS1SignatureDeformatter deformatter = new RSAPKCS1SignatureDeformatter(key);
            deformatter.SetHashAlgorithm("SHA256");
            return deformatter;
        }

        public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }

            RSAPKCS1SignatureFormatter formatter = new RSAPKCS1SignatureFormatter(key);
            formatter.SetHashAlgorithm("SHA256");
            return formatter;
        }

    }


    static bool ValidateXml(XmlDocument receipt, X509Certificate2 certificate)
    {
        // Create the signed XML object.
        SignedXml sxml = new SignedXml(receipt);

        // Get the XML Signature node and load it into the signed XML object.
        XmlNode dsig = receipt.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl)[0];
        if (dsig == null)
        {
            // If signature is not found return false
            System.Console.WriteLine("Signature not found.");
            return false;
        }

        sxml.LoadXml((XmlElement)dsig);
        
        // Check the signature
        bool isValid = sxml.CheckSignature(certificate, true);


        FieldInfo field = sxml.GetType().GetField("m_signature",
                       BindingFlags.NonPublic |
                       BindingFlags.Instance);

        var sig = (Signature)field.GetValue(sxml);
        var _ref = (Reference)sig.SignedInfo.References[0];

        //var pre = Type.GetType("System.Security.Cryptography.Xml.Utils").GetMethod("PreProcessDocumentInput");
        //pre.Invoke(null, new[] { });


        var enveloped = (XmlDsigEnvelopedSignatureTransform)_ref.TransformChain[0];

        enveloped.LoadInput(receipt);
        var outputstream = enveloped.GetOutput();

        var securityUrl = receipt.BaseURI;
        var resolver = new XmlSecureResolver(new XmlUrlResolver(), securityUrl);
        //TransformToOctetStream(Stream input, XmlResolver resolver, string baseUri)
        MethodInfo trans = _ref.TransformChain.GetType().GetMethods(BindingFlags.NonPublic | BindingFlags.Instance)[2];
        
        var stream = trans.Invoke(_ref.TransformChain, new object[] {receipt, resolver, securityUrl});


        var canontype = sig.GetType().Assembly.GetType("System.Security.Cryptography.Xml.CanonicalXml");
        var foo = Activator.CreateInstance(canontype, BindingFlags.NonPublic | BindingFlags.Instance, null, new object[] {receipt, resolver}, null);
        





        MethodInfo method = _ref.GetType().GetMethod("CalculateHashValue",
                       BindingFlags.NonPublic |
                       BindingFlags.Instance);

        FieldInfo refs = sig.GetType().GetField("m_referencedItems",
                       BindingFlags.NonPublic |
                       BindingFlags.Instance);
        var refs1 = refs.GetValue(sig);

        var res = method.Invoke(_ref, new [] {receipt, refs1});
        var str = Convert.ToBase64String((byte[])res);

        return isValid;
    }


    public static void Main(String[] args)
    {


        //calculate caninicalized xml
        
        var t = new XmlDsigEnvelopedSignatureTransform(false);
        XmlDocument doc = new XmlDocument();
        //doc.PreserveWhitespace = true;
        doc.Load(@"c:\temp\x.xml");
        t.LoadInput(doc);

        
        FieldInfo field = t.GetType().GetField("_signaturePosition", 
                         BindingFlags.NonPublic |
                         BindingFlags.Instance);


        field.SetValue(t, 1);        
        
        var res = (XmlDocument)t.GetOutput();
        var s = res.OuterXml;

        var c14 = new XmlDsigC14NTransform();
        c14.LoadInput(res);
        var mem = (MemoryStream)c14.GetOutput();

        var sha = new SHA256Managed();
        
        var byte1 = c14.GetDigestedOutput(new SHA256Managed());
        var digest1 = Convert.ToBase64String(byte1);                
        var byte2 = sha.ComputeHash(mem.ToArray());
        var digest2 = Convert.ToBase64String(byte2);
        

        var s1 = System.Text.Encoding.UTF8.GetString(mem.ToArray());        
        var byte3 = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(s1));
        var digest3 = Convert.ToBase64String(byte3);

        //return;
        

        
        //validate signature        
        
        CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        XmlDocument xmlDoc = new XmlDocument();        
        xmlDoc.Load(@"c:\temp\x.xml");
        XmlNode node = xmlDoc.DocumentElement;
        X509Certificate2 cert = new X509Certificate2(File.ReadAllBytes(@"c:\temp\x.cer"));
        bool isValid = ValidateXml(xmlDoc, cert);        
        //return;
        

        //calc hash
        var sha1 = new SHA256Managed();
        var b1 = sha1.ComputeHash(System.Text.Encoding.UTF8.GetBytes(File.ReadAllText(@"c:\temp\x_no_sig.xml")));
        var b64 = Convert.ToBase64String(b1);
    }

    // Sign an XML file and save the signature in a new file. This method does not  
    // save the public key within the XML file.  This file cannot be verified unless  
    // the verifying code has the key with which it was signed.
    public static void SignXmlFile(string FileName, string SignedFileName, RSA Key)
    {
        // Create a new XML document.
        XmlDocument doc = new XmlDocument();

        // Load the passed XML file using its name.
        doc.Load(new XmlTextReader(FileName));

        // Create a SignedXml object.
        SignedXml signedXml = new SignedXml(doc);

        // Add the key to the SignedXml document. 
        signedXml.SigningKey = Key;

        // Create a reference to be signed.
        Reference reference = new Reference();
        reference.Uri = "";

        // Add an enveloped transformation to the reference.
        XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
        reference.AddTransform(env);

        // Add the reference to the SignedXml object.
        signedXml.AddReference(reference);

        // Compute the signature.
        signedXml.ComputeSignature();

        // Get the XML representation of the signature and save
        // it to an XmlElement object.
        XmlElement xmlDigitalSignature = signedXml.GetXml();

        // Append the element to the XML document.
        doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));

        if (doc.FirstChild is XmlDeclaration)
        {
            doc.RemoveChild(doc.FirstChild);
        }

        // Save the signed XML document to a file specified
        // using the passed string.
        XmlTextWriter xmltw = new XmlTextWriter(SignedFileName, new UTF8Encoding(false));
        doc.WriteTo(xmltw);
        xmltw.Close();
    }

    // Verify the signature of an XML file against an asymetric 
    // algorithm and return the result.
    public static Boolean VerifyXmlFile(String Name, RSA Key)
    {
        // Create a new XML document.
        XmlDocument xmlDocument = new XmlDocument();

        // Load the passed XML file into the document. 
        xmlDocument.Load(Name);

        // Create a new SignedXml object and pass it
        // the XML document class.
        SignedXml signedXml = new SignedXml(xmlDocument);

        // Find the "Signature" node and create a new
        // XmlNodeList object.
        XmlNodeList nodeList = xmlDocument.GetElementsByTagName("Signature");

        // Load the signature node.
        signedXml.LoadXml((XmlElement)nodeList[0]);

        // Check the signature and return the result.
        return signedXml.CheckSignature(Key);
    }


    // Create example data to sign.
    public static void CreateSomeXml(string FileName)
    {
        // Create a new XmlDocument object.
        XmlDocument document = new XmlDocument();

        // Create a new XmlNode object.
        XmlNode node = document.CreateNode(XmlNodeType.Element, "", "MyElement", "samples");

        // Add some text to the node.
        node.InnerText = "Example text to be signed.";

        // Append the node to the document.
        document.AppendChild(node);

        // Save the XML document to the file name specified.
        XmlTextWriter xmltw = new XmlTextWriter(FileName, new UTF8Encoding(false));
        document.WriteTo(xmltw);
        xmltw.Close();
    }
}
