import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import { SignedXml } from "../src/index";
import * as fs from "fs";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";

describe("Signature integration tests", function () {
  function verifySignature(xml, expected, xpath, canonicalizationAlgorithm) {
    const sig = new SignedXml();
    sig.privateKey = fs.readFileSync("./test/static/client.pem");

    xpath.map(function (n) {
      sig.addReference({
        xpath: n,
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
      });
    });

    sig.canonicalizationAlgorithm = canonicalizationAlgorithm;
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    sig.computeSignature(xml);
    const signed = sig.getSignedXml();

    const expectedContent = fs.readFileSync(expected).toString();
    expect(signed, "signature xml different than expected").to.equal(expectedContent);
  }

  it("verify signature", function () {
    const xml =
      '<root><x xmlns="ns"></x><y z_attr="value" a_attr1="foo"></y><z><ns:w ns:attr="value" xmlns:ns="myns"></ns:w></z></root>';
    verifySignature(
      xml,
      "./test/static/integration/expectedVerify.xml",
      ["//*[local-name(.)='x']", "//*[local-name(.)='y']", "//*[local-name(.)='w']"],
      "http://www.w3.org/2001/10/xml-exc-c14n#",
    );
  });

  it("verify signature of complex element", function () {
    const xml =
      "<library>" +
      "<book>" +
      "<name>Harry Potter</name>" +
      '<author id="123456789">' +
      "<firstName>Joanne K</firstName>" +
      "<lastName>Rowling</lastName>" +
      "</author>" +
      "</book>" +
      "</library>";

    verifySignature(
      xml,
      "./test/static/integration/expectedVerifyComplex.xml",
      ["//*[local-name(.)='book']"],
      "http://www.w3.org/2001/10/xml-exc-c14n#",
    );
  });

  it("empty URI reference should consider the whole document", function () {
    const xml = "<library>" + "<book>" + "<name>Harry Potter</name>" + "</book>" + "</library>";

    const signature =
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

    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("add canonicalization if output of transforms will be a node-set rather than an octet stream", function () {
    let xml = fs.readFileSync("./test/static/windows_store_signature.xml", "utf-8");

    /** Make sure that whitespace in the source document is removed --
     * @see xml-crypto issue #23 and post at
     *   http://webservices20.blogspot.co.il/2013/06/validating-windows-mobile-app-store.html
     * This regex is naive but works for this test case; for a more general solution consider
     *   the xmldom-fork-fixed library which can pass {ignoreWhiteSpace: true} into the Dom constructor.
     */
    xml = xml.replace(/>\s*</g, "><");

    const doc = new xmldom.DOMParser().parseFromString(xml);
    const childXml = doc.firstChild?.toString();

    const signature = xpath.select1(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/windows_store_certificate.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(childXml ?? "");

    expect(result).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("signature with inclusive namespaces", function () {
    const xml = fs.readFileSync("./test/static/signature_with_inclusivenamespaces.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const childXml = doc.firstChild?.toString();

    const signature = xpath.select1(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/signature_with_inclusivenamespaces.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(childXml ?? "");

    expect(result).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("signature with inclusive namespaces with unix line separators", function () {
    const xml = fs.readFileSync(
      "./test/static/signature_with_inclusivenamespaces_lines.xml",
      "utf-8",
    );
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const childXml = doc.firstChild?.toString();

    const signature = xpath.select1(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/signature_with_inclusivenamespaces.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(childXml ?? "");

    expect(result).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("signature with inclusive namespaces with windows line separators", function () {
    const xml = fs.readFileSync(
      "./test/static/signature_with_inclusivenamespaces_lines_windows.xml",
      "utf-8",
    );
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const childXml = doc.firstChild?.toString();

    const signature = xpath.select1(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/signature_with_inclusivenamespaces.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(childXml ?? "");

    expect(result).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("should create single root xml document when signing inner node", function () {
    const xml = "<library>" + "<book>" + "<name>Harry Potter</name>" + "</book>" + "</library>";

    const sig = new SignedXml();
    sig.addReference({
      xpath: "//*[local-name(.)='book']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });
    sig.privateKey = fs.readFileSync("./test/static/client.pem");
    sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    sig.computeSignature(xml);

    const signed = sig.getSignedXml();

    const doc = new xmldom.DOMParser().parseFromString(signed);

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

    expect(doc.documentElement.nodeName, "root node = <library>.").to.equal("library");
    expect(doc.childNodes.length, "only one root node is expected.").to.equal(1);
    expect(
      doc.documentElement.childNodes.length,
      "<library> should have two child nodes : <book> and <Signature>",
    ).to.equal(2);
  });

  it("should create valid signature when signature location is nested in child element", function () {
    const xml = "<root><child/></root>";

    const sig = new SignedXml();
    sig.privateKey = fs.readFileSync("./test/static/client.pem");
    sig.addReference({
      xpath: "/*",
      transforms: [
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        "http://www.w3.org/2001/10/xml-exc-c14n#",
      ],
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    });
    sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    sig.computeSignature(xml, {
      location: { action: "append", reference: "//*[local-name()='child']" },
    });

    const signedXml = sig.getSignedXml();

    const doc = new xmldom.DOMParser().parseFromString(signedXml);
    const signatureNode = xpath.select1("//*[local-name(.)='Signature']", doc);
    isDomNode.assertIsNodeLike(signatureNode);

    const verifier = new SignedXml();
    verifier.publicCert = fs.readFileSync("./test/static/client_public.pem");
    verifier.loadSignature(signatureNode);

    expect(verifier.checkSignature(signedXml)).to.be.true;
  });

  it("should still verify a loaded signature after signing another document fails", function () {
    const signedXml = fs.readFileSync("./test/static/valid_signature.xml", "utf8");
    const doc = new xmldom.DOMParser().parseFromString(signedXml);
    const signature = xpath.select1(
      "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml({
      privateKey: fs.readFileSync("./test/static/client.pem"),
      publicCert: fs.readFileSync("./test/static/client_public.pem"),
    });
    sig.loadSignature(signature);
    expect(sig.checkSignature(signedXml)).to.be.true;

    expect(() => sig.computeSignature("<other/>")).to.throw();

    expect(sig.checkSignature(signedXml)).to.be.true;
  });

  for (const location of ["/root", "/root/container"]) {
    describe(`when appending a parent signature to ${location}`, function () {
      const privateKey = fs.readFileSync("./test/static/client.pem");
      const publicCert = fs.readFileSync("./test/static/client_public.pem");
      const select = xpath.useNamespaces({ ds: "http://www.w3.org/2000/09/xmldsig#" });
      let signedXml: string;
      let doc: Document;
      let parentSignatureXml: string;

      const createSigner = (reference: string) => {
        const signer = new SignedXml({
          privateKey,
          canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
          signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        });
        signer.addReference({
          xpath: reference,
          transforms: [
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/2001/10/xml-exc-c14n#",
          ],
          digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
        });
        return signer;
      };

      beforeEach(function () {
        const childSigner = createSigner("/root/child");
        childSigner.computeSignature(
          '<root Id="parent"><child Id="child"><value>data</value></child><container/></root>',
          { location: { reference: "/root/child", action: "append" } },
        );

        const parentSigner = createSigner("/root");
        parentSigner.computeSignature(childSigner.getSignedXml(), {
          prefix: "ds",
          location: { reference: location, action: "append" },
        });
        signedXml = parentSigner.getSignedXml();
        doc = new xmldom.DOMParser().parseFromString(signedXml);
        parentSignatureXml = parentSigner.getSignatureXml();
      });

      it("should preserve the validity of the child and parent signatures", function () {
        for (const reference of ["/root/child", location]) {
          const signature = select(`${reference}/ds:Signature`, doc, true);
          isDomNode.assertIsNodeLike(signature);
          const verifier = new SignedXml({ publicCert });
          verifier.loadSignature(signature);
          expect(verifier.checkSignature(signedXml), `signature at ${reference}`).to.be.true;
        }
      });

      it("should reject the parent signature when the child signature is tampered with", function () {
        const childSignatureValue = select("/root/child/ds:Signature/ds:SignatureValue", doc, true);
        isDomNode.assertIsElementNode(childSignatureValue);
        childSignatureValue.textContent = "tampered";
        const parentVerifier = new SignedXml({ publicCert });
        parentVerifier.loadSignature(parentSignatureXml);
        expect(parentVerifier.checkSignature(doc.toString())).to.be.false;
        expect(parentVerifier.getSignedReferences()).to.be.empty;
      });
    });
  }
});
