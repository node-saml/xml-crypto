var select = require('xpath.js')
  , Dom = require('xmldom-fork-fixed').DOMParser
  , SignedXml = require('../lib/signed-xml.js').SignedXml
  , fs = require('fs')
  , crypto = require('../index')
  
module.exports = {    


  "verify signature": function (test) {
  	var xml = "<root><x xmlns=\"ns\"></x><y z_attr=\"value\" a_attr1=\"foo\"></y><z><ns:w ns:attr=\"value\" xmlns:ns=\"myns\"></ns:w></z></root>"
    verifySignature(test, xml, "./test/static/integration/expectedVerify.xml", [
      "//*[local-name(.)='x']", 
      "//*[local-name(.)='y']", 
      "//*[local-name(.)='w']"])
  },



  "verify signature of complex element": function (test) {
    var xml = "<library>" +
                "<book>" +
                  "<name>Harry Potter</name>" +
                  "<author id=\"123456789\">" +
                    "<firstName>Joanne K</firstName>" +
                    "<lastName>Rowling</lastName>" +
                  "</author>" +
                "</book>" +
              "</library>"

    verifySignature(test, xml,  "./test/static/integration/expectedVerifyComplex.xml", ["//*[local-name(.)='book']"])
  },



  "empty URI reference should consider the whole document": function(test) {    

    var sampleXml=["<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
                           "<root>",
                           "    <a>",
                           "        <b/>",
                           "    </a>",
                           "    <Seal><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>FOezc5yb1O+LfQaD4UBKEUphrGzFAq5DM9B9ll37JOA=</DigestValue></Reference></SignedInfo><SignatureValue>AjkQ5NF71bwJ2YHIs8jbqva9qaNv66BYZiZw0JJZ1cW6jf3mjWShIMQZWcw78QGpzzr+ZspzUbs4",
                           "6VAnHApJElOTDylSf3rDSvzsklKcFpHJ9yCJV+PnipEsY8qWhzKHlKCdtEn1xH0BCP/2JfMYgLQl",
                           "PCvaR8XrgdODeQ2Gn6g=</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>t+qknJd/Kdo09fvQrRThqh/3EyDQj8zT1ZT7uXmivni4Vaysf6zHv+oORIvAt9ntZE2ZCif9v6CC",
                           "W+hmRFkdgRoVpmD2TErjykzowx6Ffyf5BkVnVB89+g/ZqNyyvXiBe8SmpBrRLOMifnbacyrJcsrH",
                           "fwlCnuyGKXj1LfzDcR8=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature></Seal>",
                           "    <c>",
                           "        <d e=\"f\"/>",
                           "    </c>",
                           "</root>"].join("\n");
    
    var doc = new Dom().parseFromString(sampleXml);    
    
    var signature = crypto.xpath(doc, "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
    var sig = new crypto.SignedXml();
    sig.keyInfoProvider = new crypto.FileKeyInfo("./test/static/empty_uri.pem");
    sig.loadSignature(signature.toString());    
    var result = sig.checkSignature(sampleXml);
    test.equal(result, true);
    test.done();
  },



  "windows store signature": function(test) {    

    var xml = fs.readFileSync('./test/static/windows_store_signature.xml', 'utf-8');        
    var doc = new Dom({ignoreWhiteSpace: true}).parseFromString(xml);    
    //ensure xml has not white space    
    xml = doc.firstChild.toString()

    var signature = crypto.xpath(doc, "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
    var sig = new crypto.SignedXml();    
    sig.keyInfoProvider = new crypto.FileKeyInfo("./test/static/windows_store_certificate.pem");
    sig.loadSignature(signature.toString());    
    var result = sig.checkSignature(xml);
    test.equal(result, true);
    test.done();
  },



  "signature with inclsuive namespaces": function(test) {    

    var xml = fs.readFileSync('./test/static/signature_with_inclusivenamespaces.xml', 'utf-8');        
    var doc = new Dom({ignoreWhiteSpace: true}).parseFromString(xml);    
    //ensure xml has not white space    
    xml = doc.firstChild.toString()

    var signature = crypto.xpath(doc, "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
    var sig = new crypto.SignedXml();    
    sig.keyInfoProvider = new crypto.FileKeyInfo("./test/static/signature_with_inclusivenamespaces.pem");
    sig.loadSignature(signature.toString());    
    var result = sig.checkSignature(xml);
    test.equal(result, true);
    test.done();
  },




  "should create single root xml document when signing inner node": function(test) {
    var xml = "<library>" +
                "<book>" +
                  "<name>Harry Potter</name>" +
                "</book>" +
              "</library>"

    var sig = new SignedXml()
    sig.addReference("//*[local-name(.)='book']")    
    sig.signingKey = fs.readFileSync("./test/static/client.pem")
    sig.computeSignature(xml)      
    
    var signed = sig.getSignedXml();
    console.log(signed);
    
    var doc = new Dom().parseFromString(signed);
    
    /*
        Expecting this structure:
        <library>
            <book Id="_0">
                <name>Harry Potter</name>
            </book>        
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                <SignedInfo>
                    <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                    <Reference URI="#_0">
                        <Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms>
                        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                        <DigestValue>cdiS43aFDQMnb3X8yaIUej3+z9Q=</DigestValue>
                    </Reference>
                </SignedInfo>
                <SignatureValue>J79hiSUrKdLOuX....Mthy1M=</SignatureValue>
            </Signature>
        </library>        
    */
     
    test.ok(doc.documentElement.nodeName == "library", "root node = <library>.");
    test.ok(doc.childNodes.length == 1, "only one root node is expected.");
    test.ok(doc.documentElement.childNodes.length == 2, "<library> should have two child nodes : <book> and <Signature>");
    
    test.done();
  }

}

function verifySignature(test, xml, expected, xpath) {  
  
  var sig = new SignedXml()
  sig.signingKey = fs.readFileSync("./test/static/client.pem")
  sig.keyInfoCaluse = null
  
  xpath.map(function(n) { sig.addReference(n) })

  sig.computeSignature(xml)
  var signed = sig.getSignedXml()

  //fs.writeFileSync("./test/validators/XmlCryptoUtilities/XmlCryptoUtilities/bin/Debug/signedExample.xml", signed)    
  var expectedContent = fs.readFileSync(expected).toString()
  test.equal(signed, expectedContent, "signature xml different than expected")
  test.done()
  /*
  var spawn = require('child_process').spawn
  var proc = spawn('./test/validators/XmlCryptoUtilities/XmlCryptoUtilities/bin/Debug/XmlCryptoUtilities.exe', ['verify'])

  proc.stdout.on('data', function (data) {
    console.log('stdout: ' + data);
  });

  proc.stderr.on('data', function (data) {
    console.log('stderr: ' + data);
  });

  proc.on('exit', function (code) {   
    test.equal(0, code, "signature validation failed")
    test.done()
  });
  */ 

}
