var xpath = require("xpath"),
  Dom = require("@xmldom/xmldom").DOMParser,
  SignedXml = require("../lib/signed-xml.js").SignedXml,
  fs = require("fs"),
  crypto = require("../index");

describe("Signature integration tests", function () {
  it("verify signature", function () {
    var xml =
      '<root><x xmlns="ns"></x><y z_attr="value" a_attr1="foo"></y><z><ns:w ns:attr="value" xmlns:ns="myns"></ns:w></z></root>';
    verifySignature(xml, "./test/static/integration/expectedVerify.xml", [
      "//*[local-name(.)='x']",
      "//*[local-name(.)='y']",
      "//*[local-name(.)='w']",
    ]);
  });

  it("verify signature of complex element", function () {
    var xml =
      "<library>" +
      "<book>" +
      "<name>Harry Potter</name>" +
      '<author id="123456789">' +
      "<firstName>Joanne K</firstName>" +
      "<lastName>Rowling</lastName>" +
      "</author>" +
      "</book>" +
      "</library>";

    verifySignature(xml, "./test/static/integration/expectedVerifyComplex.xml", [
      "//*[local-name(.)='book']",
    ]);
  });

  it("empty URI reference should consider the whole document", function () {
    var xml = "<library>" + "<book>" + "<name>Harry Potter</name>" + "</book>" + "</library>";

    var signature =
      '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' +
      "<SignedInfo>" +
      '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
      '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>' +
      '<Reference URI="">' +
      "<Transforms>" +
      '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
      "</Transforms>" +
      '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
      "<DigestValue>1tjZsV007JgvE1YFe1C8sMQ+iEg=</DigestValue>" +
      "</Reference>" +
      "</SignedInfo>" +
      "<SignatureValue>FONRc5/nnQE2GMuEV0wK5/ofUJMHH7dzZ6VVd+oHDLfjfWax/lCMzUahJxW1i/dtm9Pl0t2FbJONVd3wwDSZzy6u5uCnj++iWYkRpIEN19RAzEMD1ejfZET8j3db9NeBq2JjrPbw81Fm7qKvte6jGa9ThTTB+1MHFRkC8qjukRM=</SignatureValue>" +
      "</Signature>";

    var sig = new crypto.SignedXml();
    sig.keyInfoProvider = new crypto.FileKeyInfo("./test/static/client_public.pem");
    sig.loadSignature(signature);
    var result = sig.checkSignature(xml);

    expect(result).toBe(true);
  });

  it("add canonicalization if output of transforms will be a node-set rather than an octet stream", function () {
      var xml = fs.readFileSync("./test/static/windows_store_signature.xml", "utf-8");

      // Make sure that whitespace in the source document is removed -- see xml-crypto issue #23 and post at
      //   http://webservices20.blogspot.co.il/2013/06/validating-windows-mobile-app-store.html
      // This regex is naive but works for this test case; for a more general solution consider
      //   the xmldom-fork-fixed library which can pass {ignoreWhiteSpace: true} into the Dom constructor.
      xml = xml.replace(/>\s*</g, "><");

      var doc = new Dom().parseFromString(xml);
      xml = doc.firstChild.toString();

      var signature = xpath.select(
        "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
        doc
      )[0];
      var sig = new crypto.SignedXml();
      sig.keyInfoProvider = new crypto.FileKeyInfo("./test/static/windows_store_certificate.pem");
      sig.loadSignature(signature);
      var result = sig.checkSignature(xml);

      expect(result).toBe(true);
  });

  it("signature with inclusive namespaces", function () {
    var xml = fs.readFileSync("./test/static/signature_with_inclusivenamespaces.xml", "utf-8");
    var doc = new Dom().parseFromString(xml);
    xml = doc.firstChild.toString();

    var signature = xpath.select(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )[0];
    var sig = new crypto.SignedXml();
    sig.keyInfoProvider = new crypto.FileKeyInfo(
      "./test/static/signature_with_inclusivenamespaces.pem"
    );
    sig.loadSignature(signature);
    var result = sig.checkSignature(xml);

    expect(result).toBe(true);
  });

  it("signature with inclusive namespaces with unix line separators", function () {
    var xml = fs.readFileSync(
      "./test/static/signature_with_inclusivenamespaces_lines.xml",
      "utf-8"
    );
    var doc = new Dom().parseFromString(xml);
    xml = doc.firstChild.toString();

    var signature = xpath.select(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )[0];
    var sig = new crypto.SignedXml();
    sig.keyInfoProvider = new crypto.FileKeyInfo(
      "./test/static/signature_with_inclusivenamespaces.pem"
    );
    sig.loadSignature(signature);
    var result = sig.checkSignature(xml);

    expect(result).toBe(true);
  });

  it("signature with inclusive namespaces with windows line separators", function () {
    var xml = fs.readFileSync(
      "./test/static/signature_with_inclusivenamespaces_lines_windows.xml",
      "utf-8"
    );
    var doc = new Dom().parseFromString(xml);
    xml = doc.firstChild.toString();

    var signature = xpath.select(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )[0];
    var sig = new crypto.SignedXml();
    sig.keyInfoProvider = new crypto.FileKeyInfo(
      "./test/static/signature_with_inclusivenamespaces.pem"
    );
    sig.loadSignature(signature);
    var result = sig.checkSignature(xml);

    expect(result).toBe(true);
  });

  it("should create single root xml document when signing inner node", function () {
    var xml = "<library>" + "<book>" + "<name>Harry Potter</name>" + "</book>" + "</library>";

    var sig = new SignedXml();
    sig.addReference("//*[local-name(.)='book']");
    sig.signingKey = fs.readFileSync("./test/static/client.pem");
    sig.computeSignature(xml);

    var signed = sig.getSignedXml();

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

    expect(doc.documentElement.nodeName).withContext("root node = <library>.").toBe("library");
    expect(doc.childNodes.length).withContext("only one root node is expected.").toBe(1);
    expect(doc.documentElement.childNodes.length)
        .withContext("<library> should have two child nodes : <book> and <Signature>")
        .toBe(2);
  });
});

function verifySignature(xml, expected, xpath) {
  var sig = new SignedXml();
  sig.signingKey = fs.readFileSync("./test/static/client.pem");
  sig.keyInfo = null;

  xpath.map(function (n) {
    sig.addReference(n);
  });

  sig.computeSignature(xml);
  var signed = sig.getSignedXml();

  //fs.writeFileSync("./test/validators/XmlCryptoUtilities/XmlCryptoUtilities/bin/Debug/signedExample.xml", signed)
  var expectedContent = fs.readFileSync(expected).toString();
  expect(signed).withContext("signature xml different than expected").toEqual(expectedContent);
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
