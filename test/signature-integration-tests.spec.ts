import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import {
  C14nCanonicalization,
  ComputeSignatureOptionsLocation,
  SignedXml,
  SignedXmlOptions,
} from "../src/index";
import * as crypto from "crypto";
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
    // The parser normalizes line endings, so only the fixture decides which kind this covers.
    expect(xml).to.not.include("\r");
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
    expect(xml).to.include("\r\n");
    expect(xml).to.not.match(/\r(?!\n)|(?<!\r)\n/);
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

  it("should create valid signature when enveloped-signature is the only transform", function () {
    const xml = "<root b='2' a='1'/>";

    const sig = new SignedXml({
      privateKey: fs.readFileSync("./test/static/client.pem"),
      canonicalizationAlgorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
      signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    });
    sig.addReference({
      xpath: "/*",
      transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"],
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      isEmptyUri: true,
    });
    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    const doc = new xmldom.DOMParser().parseFromString(signedXml);
    const signatureNode = xpath.select1("//*[local-name(.)='Signature']", doc);
    isDomNode.assertIsNodeLike(signatureNode);

    const verifier = new SignedXml();
    verifier.publicCert = fs.readFileSync("./test/static/client_public.pem");
    verifier.loadSignature(signatureNode);

    expect(verifier.checkSignature(signedXml)).to.be.true;
    expect(verifier.getSignedReferences()).to.deep.equal(['<root a="1" b="2"></root>']);
  });

  it("should keep inherited namespaces when enveloped-signature is the only transform", function () {
    const sig = new SignedXml({
      privateKey: fs.readFileSync("./test/static/client.pem"),
      canonicalizationAlgorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
      signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    });
    sig.addReference({
      xpath: "//*[local-name(.)='item']",
      transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"],
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    });
    sig.computeSignature(
      "<root xmlns='urn:x' xmlns:p='urn:p'><item Id='item' b='2' a='1'/></root>",
    );

    const verifier = new SignedXml({
      publicCert: fs.readFileSync("./test/static/client_public.pem"),
    });
    verifier.loadSignature(sig.getSignatureXml());

    expect(verifier.checkSignature(sig.getSignedXml())).to.be.true;
    expect(verifier.getSignedReferences()).to.deep.equal([
      '<item xmlns="urn:x" xmlns:p="urn:p" Id="item" a="1" b="2"></item>',
    ]);
  });

  describe("transforms that follow a canonicalization", function () {
    class DropNotes {
      process(node: Node) {
        const notes = xpath.select(".//note", node);
        isDomNode.assertIsArrayOfNodes(notes);
        notes.forEach((note) => note.parentNode?.removeChild(note));
        return node;
      }

      getAlgorithmName() {
        return "urn:test:drop-notes";
      }
    }

    class ReverseSignaturesToString {
      process(node: Node) {
        const signatures = xpath.select("./*[local-name(.)='Signature']", node);
        isDomNode.assertIsArrayOfNodes(signatures);
        signatures.reverse().forEach((signature) => node.appendChild(signature));
        return node.toString();
      }

      getAlgorithmName() {
        return "urn:test:reverse-signatures";
      }
    }

    function signAndVerify(xml: string, xpathToSign: string, transforms: string[]) {
      const sig = new SignedXml({
        privateKey: fs.readFileSync("./test/static/client.pem"),
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      });
      sig.CanonicalizationAlgorithms["urn:test:drop-notes"] = DropNotes;
      sig.CanonicalizationAlgorithms["urn:test:reverse-signatures"] = ReverseSignaturesToString;
      sig.addReference({
        xpath: xpathToSign,
        transforms,
        digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      });
      sig.computeSignature(xml);

      const verifier = new SignedXml({
        publicCert: fs.readFileSync("./test/static/client_public.pem"),
      });
      verifier.CanonicalizationAlgorithms["urn:test:drop-notes"] = DropNotes;
      verifier.CanonicalizationAlgorithms["urn:test:reverse-signatures"] =
        ReverseSignaturesToString;
      verifier.loadSignature(sig.getSignatureXml());
      const valid = verifier.checkSignature(sig.getSignedXml());

      return { valid, signedReferences: verifier.getSignedReferences() };
    }

    // https://github.com/node-saml/xml-crypto/issues/111
    it("should verify an enveloped signature removed after canonicalization", function () {
      const result = signAndVerify("<root><x>1</x></root>", "/*", [
        "http://www.w3.org/2001/10/xml-exc-c14n#",
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      ]);

      expect(result.valid).to.be.true;
      expect(result.signedReferences).to.deep.equal(['<root Id="_0"><x>1</x></root>']);
    });

    it("should remove the verified signature after a custom transform reorders signatures", function () {
      const otherSignature =
        '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignatureValue>other</SignatureValue></Signature>';
      const result = signAndVerify(`<root><x>1</x>${otherSignature}</root>`, "/*", [
        "urn:test:reverse-signatures",
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      ]);

      expect(result.valid).to.be.true;
      expect(result.signedReferences).to.deep.equal([
        `<root Id="_0"><x>1</x>${otherSignature}</root>`,
      ]);
    });

    it("should apply a custom transform that follows a canonicalization", function () {
      const result = signAndVerify(
        "<root><data><x>1</x><note>draft</note></data></root>",
        "//*[local-name(.)='data']",
        ["http://www.w3.org/2001/10/xml-exc-c14n#", "urn:test:drop-notes"],
      );

      expect(result.valid).to.be.true;
      expect(result.signedReferences).to.deep.equal(['<data Id="_0"><x>1</x></data>']);
    });

    // Signed by .NET's SignedXml with client.pem, so a mistake this library's signer and verifier
    // share cannot hide behind a round trip.
    for (const { fixture, signedReference } of [
      {
        fixture: "dotnet_enveloped_signature_after_exc_c14n.xml",
        signedReference: "<root><x>1</x></root>",
      },
      {
        fixture: "dotnet_enveloped_signature_after_c14n.xml",
        signedReference: '<item xmlns="urn:x" xmlns:p="urn:p" Id="i"><p:a>1</p:a></item>',
      },
    ]) {
      it(`should verify ${fixture}`, function () {
        const xml = fs.readFileSync(`./test/static/${fixture}`, "utf8");
        const verifier = new SignedXml({
          publicCert: fs.readFileSync("./test/static/client_public.pem"),
        });
        verifier.loadSignature(
          verifier.findSignatures(new xmldom.DOMParser().parseFromString(xml))[0],
        );

        expect(verifier.checkSignature(xml)).to.be.true;
        expect(verifier.getSignedReferences()).to.deep.equal([signedReference]);
      });
    }

    it("should not restore ancestor namespaces that exclusive canonicalization omitted", function () {
      const result = signAndVerify(
        "<root xmlns:p='urn:p'><item/></root>",
        "//*[local-name(.)='item']",
        [
          "http://www.w3.org/2001/10/xml-exc-c14n#",
          "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        ],
      );

      expect(result.valid).to.be.true;
      expect(result.signedReferences).to.deep.equal(['<item Id="_0"></item>']);
    });
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

  const envelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
  const exclusiveCanonicalization = "http://www.w3.org/2001/10/xml-exc-c14n#";
  const envelopedTransformOrders = [
    [envelopedSignature, exclusiveCanonicalization],
    [exclusiveCanonicalization, envelopedSignature],
  ];

  describe("copies of the enveloped signature", function () {
    function sign(xml: string, reference: string, transforms: string[]) {
      const signer = new SignedXml({
        privateKey: fs.readFileSync("./test/static/client.pem"),
        canonicalizationAlgorithm: exclusiveCanonicalization,
        signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      });
      signer.addReference({
        xpath: reference,
        transforms,
        digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      });
      signer.computeSignature(xml);
      return { signedXml: signer.getSignedXml(), signatureXml: signer.getSignatureXml() };
    }

    function injectCopy(signedXml: string, signatureXml: string, after: string) {
      const copy = signatureXml.replace("<SignedInfo>", "<role>admin</role><SignedInfo>");
      return signedXml.replace(after, `${after}${copy}`);
    }

    function createVerifier(signature: Node | string) {
      const verifier = new SignedXml({
        publicCert: fs.readFileSync("./test/static/client_public.pem"),
      });
      verifier.loadSignature(signature);
      return verifier;
    }

    const lastSignatureIn = (xml: string) =>
      new SignedXml().findSignatures(new xmldom.DOMParser().parseFromString(xml)).pop() as Node;
    const firstSignatureIn = (xml: string) =>
      new SignedXml().findSignatures(new xmldom.DOMParser().parseFromString(xml))[0];

    for (const transforms of envelopedTransformOrders) {
      const order = transforms[0] === envelopedSignature ? "before" : "after";

      for (const loadFrom of ["the document", "a string"]) {
        it(`should reject a copy inside the signed element, enveloped-signature ${order} canonicalization, signature loaded from ${loadFrom}`, function () {
          const { signedXml, signatureXml } = sign(
            "<root><role>user</role></root>",
            "/*",
            transforms,
          );
          const tampered = injectCopy(signedXml, signatureXml, "<role>user</role>");

          const verifier = createVerifier(
            loadFrom === "a string" ? signatureXml : lastSignatureIn(tampered),
          );
          expect(() => verifier.checkSignature(tampered)).to.throw(
            "Cannot validate a document which contains multiple Signature elements with the same SignatureValue",
          );
          expect(verifier.getSignedReferences()).to.be.empty;
          expect(createVerifier(signatureXml).checkSignature(signedXml)).to.be.true;
        });
      }

      it(`should reject a copy inside a signed element the signature is outside of, enveloped-signature ${order} canonicalization`, function () {
        const { signedXml, signatureXml } = sign(
          "<response><assertion><role>user</role></assertion></response>",
          "//assertion",
          transforms,
        );
        const tampered = injectCopy(signedXml, signatureXml, "<role>user</role>");

        const verifier = createVerifier(lastSignatureIn(tampered));
        expect(() => verifier.checkSignature(tampered)).to.throw(
          "Cannot validate a document which contains multiple Signature elements with the same SignatureValue",
        );
        expect(verifier.getSignedReferences()).to.be.empty;
      });

      it(`should reject a copy whose SignatureValue differs only in whitespace, enveloped-signature ${order} canonicalization`, function () {
        const { signedXml, signatureXml } = sign(
          "<response><assertion><role>user</role></assertion></response>",
          "//assertion",
          transforms,
        );
        const rewrapped = signatureXml.replace(/<SignatureValue>(.{40})/, "<SignatureValue>$1\n");
        const tampered = injectCopy(signedXml, rewrapped, "<role>user</role>");

        const verifier = createVerifier(firstSignatureIn(tampered));
        expect(() => verifier.checkSignature(tampered)).to.throw(
          "Cannot validate a document which contains multiple Signature elements with the same SignatureValue",
        );
        expect(verifier.getSignedReferences()).to.be.empty;
      });

      it(`should reject a copy that nests the genuine SignatureValue ahead of its own, enveloped-signature ${order} canonicalization`, function () {
        const { signedXml, signatureXml } = sign(
          "<response><assertion><role>user</role></assertion></response>",
          "//assertion",
          transforms,
        );
        const nested = signatureXml.replace(
          /<SignatureValue>[^<]*<\/SignatureValue>/,
          (genuine) => `<Object>${genuine}</Object><SignatureValue>AAAA</SignatureValue>`,
        );
        const tampered = injectCopy(signedXml, nested, "<role>user</role>");

        const verifier = createVerifier(firstSignatureIn(tampered));
        expect(() => verifier.checkSignature(tampered)).to.throw(/invalid signature/);
        expect(verifier.getSignedReferences()).to.be.empty;
      });
    }
  });

  for (const transforms of envelopedTransformOrders) {
    for (const location of ["/root", "/root/container"]) {
      describe(`when appending a parent signature to ${location}, enveloped-signature ${transforms[0] === envelopedSignature ? "before" : "after"} canonicalization`, function () {
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
            transforms,
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
          const childSignatureValue = select(
            "/root/child/ds:Signature/ds:SignatureValue",
            doc,
            true,
          );
          isDomNode.assertIsElementNode(childSignatureValue);
          childSignatureValue.textContent = "tampered";
          const parentVerifier = new SignedXml({ publicCert });
          parentVerifier.loadSignature(parentSignatureXml);
          expect(parentVerifier.checkSignature(doc.toString())).to.be.false;
          expect(parentVerifier.getSignedReferences()).to.be.empty;
        });
      });
    }
  }

  // A signed reference must hand back the element in the namespace it was signed in. If a
  // hoisted ancestor default namespace leaks into a descendant, the signature still verifies
  // while `getSignedReferences()` reports an identity the sender never signed — and a caller
  // that dispatches on element namespace acts on it.
  // https://www.w3.org/TR/xml-c14n/#ProcessingModel
  it("does not move an element into a namespace it was not signed in", function () {
    const c14n = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    const xml = '<root xmlns="urn:A"><p:x xmlns:p="urn:p" Id="_1"><y xmlns=""></y></p:x></root>';

    const sig = new SignedXml();
    sig.privateKey = fs.readFileSync("./test/static/client.pem");
    sig.canonicalizationAlgorithm = c14n;
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: [c14n],
    });
    sig.computeSignature(xml);
    const signed = sig.getSignedXml();

    const signature = xpath.select1(
      "//*[local-name(.)='Signature']",
      new xmldom.DOMParser().parseFromString(signed),
    );
    isDomNode.assertIsNodeLike(signature);

    const verify = new SignedXml();
    verify.publicCert = fs.readFileSync("./test/static/client_public.pem");
    verify.loadSignature(signature);
    expect(verify.checkSignature(signed)).to.be.true;

    const trusted = new xmldom.DOMParser().parseFromString(verify.getSignedReferences()[0]);
    const y = xpath.select1("//*[local-name(.)='y']", trusted);
    isDomNode.assertIsElementNode(y);
    expect(y.namespaceURI ?? "", "<y> must stay in no namespace").to.equal("");
  });

  describe("comments in same-document references", function () {
    const enveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

    type Algorithms = SignedXml["CanonicalizationAlgorithms"];

    function sign(
      xml: string,
      reference: { xpath: string; transforms: string[]; isEmptyUri?: boolean },
      {
        canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#",
        algorithms = {},
      }: { canonicalizationAlgorithm?: string; algorithms?: Algorithms } = {},
    ) {
      const signer = new SignedXml({
        privateKey: fs.readFileSync("./test/static/client.pem"),
        canonicalizationAlgorithm,
        signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      });
      Object.assign(signer.CanonicalizationAlgorithms, algorithms);
      signer.addReference({
        ...reference,
        digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      });
      signer.computeSignature(xml);
      return signer.getSignedXml();
    }

    function verify(signedXml: string, algorithms: Algorithms = {}) {
      const verifier = new SignedXml({
        publicCert: fs.readFileSync("./test/static/client_public.pem"),
      });
      Object.assign(verifier.CanonicalizationAlgorithms, algorithms);
      verifier.loadSignature(
        verifier.findSignatures(new xmldom.DOMParser().parseFromString(signedXml))[0],
      );
      expect(verifier.checkSignature(signedXml)).to.be.true;
      return verifier.getSignedReferences();
    }

    for (const withComments of [
      "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
    ]) {
      // https://www.w3.org/TR/xmldsig-core1/#sec-Same-Document
      it(`should not sign comments through URI="" with ${withComments}`, function () {
        const signedXml = sign("<root><!-- draft --><x>1</x></root>", {
          xpath: "/*",
          transforms: [enveloped, withComments],
          isEmptyUri: true,
        });

        expect(verify(signedXml)).to.deep.equal(["<root><x>1</x></root>"]);
        expect(verify(signedXml.replace("draft", "final"))).to.deep.equal([
          "<root><x>1</x></root>",
        ]);
      });

      it(`should not sign comments through an ID reference with ${withComments}`, function () {
        const signedXml = sign("<root><item><!-- draft --><x>1</x></item></root>", {
          xpath: "//item",
          transforms: [withComments],
        });

        expect(verify(signedXml)).to.deep.equal(['<item Id="_0"><x>1</x></item>']);
        expect(verify(signedXml.replace("draft", "final"))).to.deep.equal([
          '<item Id="_0"><x>1</x></item>',
        ]);
      });
    }

    it("should remove comments before the first transform", function () {
      const transformInputs: string[] = [];
      class RecordInput {
        process(node: Node) {
          transformInputs.push(node.toString());
          return node;
        }

        getAlgorithmName() {
          return "urn:test:record-input";
        }
      }
      const algorithms = { "urn:test:record-input": RecordInput };

      const signedXml = sign(
        "<root><item><!-- draft --><x>1</x></item></root>",
        {
          xpath: "//item",
          transforms: [
            "urn:test:record-input",
            "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
          ],
        },
        { algorithms },
      );
      verify(signedXml, algorithms);

      expect(transformInputs).to.deep.equal([
        '<item Id="_0"><x>1</x></item>',
        '<item Id="_0"><x>1</x></item>',
      ]);
    });

    it("should still sign comments in SignedInfo with a WithComments CanonicalizationMethod", function () {
      const signedXml = sign(
        "<root><x>1</x></root>",
        { xpath: "//x", transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"] },
        { canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" },
      );
      expect(verify(signedXml)).to.deep.equal(['<x Id="_0">1</x>']);

      const tampered = signedXml.replace("<SignedInfo>", "<SignedInfo><!-- added -->");
      expect(() => verify(tampered)).to.throw(/the signature value .* is incorrect/);
    });
  });

  describe("reference selection and detached signatures", function () {
    const privateKey = fs.readFileSync("./test/static/client.pem");
    const publicCert = fs.readFileSync("./test/static/client_public.pem");
    const canonicalization = "http://www.w3.org/2001/10/xml-exc-c14n#";
    const enveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

    for (const useCallback of [false, true]) {
      describe(useCallback ? "with a callback" : "without a callback", function () {
        for (const { name, reference, detached } of [
          { name: "signs all input elements", reference: "//*", detached: false },
          {
            name: "signs an element selected by the absence of an ID",
            reference: "/root[not(@Id)]",
            detached: false,
          },
          {
            name: "creates a verifiable detached signature",
            reference: "/*",
            detached: "generated IDs",
          },
          {
            name: "creates a verifiable detached signature over elements that carry their IDs",
            reference: "/*",
            detached: "input IDs",
          },
        ] as const) {
          it(name, async function () {
            const signer = new SignedXml({
              privateKey,
              canonicalizationAlgorithm: canonicalization,
              signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            });
            signer.addReference({
              xpath: reference,
              transforms: detached ? [canonicalization] : [enveloped, canonicalization],
              digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
            });

            const xml =
              detached === "input IDs" ? '<root Id="_0">trusted</root>' : "<root>trusted</root>";
            if (useCallback) {
              await new Promise<void>((resolve, reject) => {
                signer.computeSignature(xml, (err) => (err ? reject(err) : resolve()));
              });
            } else {
              signer.computeSignature(xml);
            }

            const signedXml = !detached
              ? signer.getSignedXml()
              : detached === "input IDs"
                ? xml
                : // eslint-disable-next-line deprecation/deprecation
                  signer.getOriginalXmlWithIds();
            const verifier = new SignedXml({ publicCert });
            verifier.loadSignature(signer.getSignatureXml());

            expect(verifier.checkSignature(signedXml)).to.be.true;
            expect(verifier.getSignedReferences()).to.deep.equal(['<root Id="_0">trusted</root>']);
            expect(verifier.checkSignature(signedXml.replace("trusted", "tampered"))).to.be.false;
            expect(verifier.getSignedReferences()).to.be.empty;
          });
        }
      });
    }

    it("prefers an input match over generated signature content for the same xpath", function () {
      const signer = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: canonicalization,
        signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        objects: [{ content: "<value>generated</value>", attributes: { Id: "generated" } }],
      });
      signer.addReference({
        xpath: "//*[local-name(.)='Object']",
        transforms: [canonicalization],
        digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      });

      signer.computeSignature("<root><Object>input data</Object></root>");

      const verifier = new SignedXml({ publicCert });
      verifier.loadSignature(signer.getSignatureXml());
      expect(verifier.checkSignature(signer.getSignedXml())).to.be.true;
      expect(verifier.getSignedReferences()).to.deep.equal(['<Object Id="_0">input data</Object>']);
    });

    for (const objectFirst of [false, true]) {
      it(`preserves input targets alongside an Object reference placed ${objectFirst ? "first" : "last"}`, function () {
        const signer = new SignedXml({
          privateKey,
          canonicalizationAlgorithm: canonicalization,
          signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
          objects: [{ content: "<value>object-data</value>" }],
        });
        const inputReference = {
          xpath: "//*",
          transforms: [enveloped, canonicalization],
          digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
        };
        const objectReference = {
          xpath: "//*[local-name(.)='Object']",
          transforms: [canonicalization],
          digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
        };
        for (const reference of objectFirst
          ? [objectReference, inputReference]
          : [inputReference, objectReference]) {
          signer.addReference(reference);
        }

        signer.computeSignature("<root><value>trusted</value></root>");

        const signedXml = signer.getSignedXml();
        const verifier = new SignedXml({ publicCert });
        verifier.loadSignature(signer.getSignatureXml());
        expect(verifier.checkSignature(signedXml)).to.be.true;
        const signedElements = verifier
          .getSignedReferences()
          .map((xml) => new xmldom.DOMParser().parseFromString(xml).documentElement.localName);
        expect(signedElements).to.deep.equal(
          objectFirst ? ["Object", "root", "value"] : ["root", "value", "Object"],
        );
        for (const content of ["trusted", "object-data"]) {
          expect(verifier.checkSignature(signedXml.replace(content, "tampered"))).to.be.false;
          expect(verifier.getSignedReferences()).to.be.empty;
        }
      });
    }

    for (const objectFirst of [false, true]) {
      it(`signs an Object and an element inside it with the ${objectFirst ? "Object" : "element"} referenced first`, function () {
        const signer = new SignedXml({
          privateKey,
          canonicalizationAlgorithm: canonicalization,
          signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
          objects: [{ content: "<value>object-data</value>" }],
        });
        const objectReference = "//*[local-name(.)='Object']";
        const valueReference = "//*[local-name(.)='value']";
        for (const xpath of objectFirst
          ? [objectReference, valueReference]
          : [valueReference, objectReference]) {
          signer.addReference({
            xpath,
            transforms: [canonicalization],
            digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
          });
        }

        signer.computeSignature("<root>trusted</root>");

        const signedXml = signer.getSignedXml();
        const verifier = new SignedXml({ publicCert });
        verifier.loadSignature(signer.getSignatureXml());
        expect(verifier.checkSignature(signedXml)).to.be.true;
        const signedElements = verifier
          .getSignedReferences()
          .map((xml) => new xmldom.DOMParser().parseFromString(xml).documentElement.localName);
        expect(signedElements).to.deep.equal(
          objectFirst ? ["Object", "value"] : ["value", "Object"],
        );
        expect(verifier.checkSignature(signedXml.replace("object-data", "tampered"))).to.be.false;
        expect(verifier.getSignedReferences()).to.be.empty;
      });
    }

    for (const references of [
      ["/*", "/root[not(@Id)]"],
      ["/root[not(@Id)]", "/*"],
    ]) {
      it(`resolves every reference against the input document with ${references[0]} first`, function () {
        const signer = new SignedXml({
          privateKey,
          canonicalizationAlgorithm: canonicalization,
          signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        });
        for (const xpath of references) {
          signer.addReference({
            xpath,
            transforms: [enveloped, canonicalization],
            digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
          });
        }

        signer.computeSignature("<root>trusted</root>");

        const verifier = new SignedXml({ publicCert });
        verifier.loadSignature(signer.getSignatureXml());
        expect(verifier.checkSignature(signer.getSignedXml())).to.be.true;
        expect(verifier.getSignedReferences()).to.deep.equal([
          '<root Id="_0">trusted</root>',
          '<root Id="_0">trusted</root>',
        ]);
      });
    }

    for (const references of [
      ["//*[@Id]", "/*"],
      ["/*", "//*[@Id]"],
    ]) {
      it(`rejects a reference that matches an input element only after IDs are added, with ${references[0]} first`, function () {
        const signer = new SignedXml({
          privateKey,
          canonicalizationAlgorithm: canonicalization,
          signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        });
        for (const xpath of references) {
          signer.addReference({
            xpath,
            transforms: [enveloped, canonicalization],
            digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
          });
        }

        expect(() => signer.computeSignature("<root>trusted</root>")).to.throw(
          "the following xpath cannot be signed because it was not found: //*[@Id]",
        );
      });
    }

    it("signs an element its reference selects in the input that an ID added for another reference excludes", function () {
      const signer = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: canonicalization,
        signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      });
      for (const xpath of ["/root/b", "/root/c | /root/a[not(../b/@Id)]"]) {
        signer.addReference({
          xpath,
          transforms: [canonicalization],
          digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
        });
      }

      signer.computeSignature("<root><a>A</a><b>B</b><c>C</c></root>");

      const signedXml = signer.getSignedXml();
      const verifier = new SignedXml({ publicCert });
      verifier.loadSignature(signer.getSignatureXml());
      expect(verifier.checkSignature(signedXml)).to.be.true;
      expect(verifier.getSignedReferences()).to.deep.equal([
        '<b Id="_0">B</b>',
        '<a Id="_1">A</a>',
        '<c Id="_2">C</c>',
      ]);
      expect(verifier.checkSignature(signedXml.replace(">A<", ">tampered<"))).to.be.false;
      expect(verifier.getSignedReferences()).to.be.empty;
    });

    it("retains ancestor namespaces when adding an ID changes the reference XPath's result", function () {
      const signer = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: canonicalization,
        signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      });
      signer.addReference({
        xpath: "/root/item[not(@Id)]",
        transforms: ["http://www.w3.org/TR/2001/REC-xml-c14n-20010315"],
        digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      });

      signer.computeSignature('<root xmlns:unused="urn:unused"><item>trusted</item></root>');

      const verifier = new SignedXml({ publicCert });
      verifier.loadSignature(signer.getSignatureXml());
      expect(verifier.checkSignature(signer.getSignedXml())).to.be.true;
      expect(verifier.getSignedReferences()).to.deep.equal([
        '<item xmlns:unused="urn:unused" Id="_0">trusted</item>',
      ]);
    });

    it("preserves an existing signature when reusing the signer to sign its output", function () {
      const signer = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: canonicalization,
        signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      });
      signer.addReference({
        xpath: "/*",
        transforms: [enveloped, canonicalization],
        digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      });
      signer.computeSignature("<root>trusted</root>");
      const originalSignature = signer.getSignatureXml();

      signer.computeSignature(signer.getSignedXml());

      const verifier = new SignedXml({ publicCert });
      verifier.loadSignature(signer.getSignatureXml());
      expect(verifier.checkSignature(signer.getSignedXml())).to.be.true;
      expect(
        verifier.checkSignature(
          signer
            .getSignedXml()
            .replace(
              originalSignature,
              originalSignature.replace("SignatureValue>", "SignatureValue>tampered"),
            ),
        ),
      ).to.be.false;
      expect(verifier.getSignedReferences()).to.be.empty;
    });

    it("rejects a reference that matches an input element only after the signature is inserted", function () {
      const signer = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: canonicalization,
        signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      });
      signer.addReference({
        xpath: "/root",
        transforms: [enveloped, canonicalization],
        digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      });
      signer.addReference({
        xpath: "/root/*[2]",
        transforms: [canonicalization],
        digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      });

      expect(() =>
        signer.computeSignature("<root><value>trusted</value></root>", {
          location: { reference: "/root", action: "prepend" },
        }),
      ).to.throw("the following xpath cannot be signed because it was not found: /root/*[2]");
    });
  });

  describe("carriage returns in signed text", function () {
    const canonicalization = "http://www.w3.org/2001/10/xml-exc-c14n#";

    function createSigner(options: { objects?: SignedXmlOptions["objects"] } = {}) {
      const signer = new SignedXml({
        privateKey: fs.readFileSync("./test/static/client.pem"),
        canonicalizationAlgorithm: canonicalization,
        signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        ...options,
      });
      signer.addReference({
        xpath: "//*[@Id='data' or local-name(.)='item']",
        transforms: [canonicalization],
        digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      });
      return signer;
    }

    function verify(signatureXml: string, signedXml: string) {
      const verifier = new SignedXml({
        publicCert: fs.readFileSync("./test/static/client_public.pem"),
      });
      verifier.loadSignature(signatureXml);
      expect(verifier.checkSignature(signedXml)).to.be.true;
      return verifier.getSignedReferences();
    }

    for (const useCallback of [false, true]) {
      it(`should keep them in getSignedXml()${useCallback ? " with a callback" : ""}`, async function () {
        const signer = createSigner();
        const xml = "<root><item>a&#13;b&#13;&#10;c</item></root>";
        if (useCallback) {
          await new Promise<void>((resolve, reject) => {
            signer.computeSignature(xml, (err) => (err ? reject(err) : resolve()));
          });
        } else {
          signer.computeSignature(xml);
        }

        expect(verify(signer.getSignatureXml(), signer.getSignedXml())).to.deep.equal([
          '<item Id="_0">a&#xD;b&#xD;\nc</item>',
        ]);
      });
    }

    it("should keep them in the Object content of getSignatureXml()", function () {
      const signer = createSigner({
        objects: [{ content: "<value>a&#13;b</value>", attributes: { Id: "data" } }],
      });
      signer.computeSignature("<root/>");

      const signatureXml = signer.getSignatureXml();
      expect(verify(signatureXml, signatureXml)).to.deep.equal([
        '<Object xmlns="http://www.w3.org/2000/09/xmldsig#" Id="data"><value>a&#xD;b</value></Object>',
      ]);
    });
  });

  it("rejects a document where a default id attribute repeats the id held in idAttribute", function () {
    const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
    const idAttribute = "AssertionID";
    const signer = new SignedXml({
      idAttribute,
      privateKey: fs.readFileSync("./test/static/client.pem"),
      canonicalizationAlgorithm: exclusiveC14n,
      signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    });
    signer.addReference({
      xpath: "//*[local-name(.)='book']",
      transforms: [exclusiveC14n],
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    });
    signer.computeSignature(
      '<library><book AssertionID="b1"><title>Harry Potter</title></book></library>',
    );
    const signed = signer
      .getSignedXml()
      .replace("</library>", '<book Id="b1"><title>Forged</title></book></library>');

    const verifier = new SignedXml({
      idAttribute,
      publicCert: fs.readFileSync("./test/static/client_public.pem"),
    });
    verifier.loadSignature(signer.getSignatureXml());

    expect(() => verifier.checkSignature(signed)).to.throw(
      /in order to prevent signature wrapping attack/,
    );
  });

  it("rejects a document whose copy of the loaded signature has no SignedInfo", function () {
    const sig = new SignedXml({
      privateKey: fs.readFileSync("./test/static/client.pem"),
      canonicalizationAlgorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
      signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    });
    sig.addReference({
      xpath: "/*",
      transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"],
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    });
    sig.computeSignature("<root xmlns:p='urn:p'><item>trusted</item></root>");

    const doc = new xmldom.DOMParser().parseFromString(sig.getSignedXml());
    const signedInfo = xpath.select1("//*[local-name(.)='SignedInfo']", doc);
    isDomNode.assertIsNodeLike(signedInfo);
    signedInfo.parentNode?.removeChild(signedInfo);
    const tampered = doc.toString();

    const verifier = new SignedXml({
      publicCert: fs.readFileSync("./test/static/client_public.pem"),
    });
    verifier.loadSignature(sig.getSignatureXml());

    expect(() => verifier.checkSignature(tampered)).to.throw(
      /could not find SignedInfo element in the message/,
    );
  });

  describe("a loaded signature whose SignatureValue is wrapped differently in the checked document", function () {
    const publicCert = fs.readFileSync("./test/static/client_public.pem");

    function signWithInheritedNamespace() {
      const sig = new SignedXml({
        privateKey: fs.readFileSync("./test/static/client.pem"),
        canonicalizationAlgorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      });
      sig.addReference({
        xpath: "//*[local-name(.)='item']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      });
      sig.computeSignature('<root xmlns:q="urn:q"><item>trusted</item></root>');
      return sig;
    }

    const wrapSignatureValue = (xml: string) =>
      xml.replace(/<SignatureValue>(.{40})/, "<SignatureValue>$1\n");

    it("verifies it in the namespace context it has in the checked document", function () {
      const sig = signWithInheritedNamespace();
      const verifier = new SignedXml({ publicCert });
      verifier.loadSignature(sig.getSignatureXml());

      expect(verifier.checkSignature(wrapSignatureValue(sig.getSignedXml()))).to.be.true;
    });

    it("rejects it when it is valid only in the loaded copy's namespace context", function () {
      const sig = signWithInheritedNamespace();
      const verifier = new SignedXml({ publicCert });
      verifier.loadSignature(
        verifier.findSignatures(new xmldom.DOMParser().parseFromString(sig.getSignedXml()))[0],
      );
      const withoutNamespace = sig.getSignedXml().replace(' xmlns:q="urn:q"', "");

      expect(() => verifier.checkSignature(wrapSignatureValue(withoutNamespace))).to.throw(
        /invalid signature/,
      );
    });
  });

  describe("inclusive canonicalization of SignedInfo in a document with two signatures", function () {
    const c14n = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    const samlp = "urn:oasis:names:tc:SAML:2.0:protocol";
    const saml = "urn:oasis:names:tc:SAML:2.0:assertion";
    const unsigned =
      `<samlp:Response xmlns:samlp="${samlp}" xmlns:saml="${saml}" ID="_r1">` +
      "<saml:Issuer>idp</saml:Issuer>" +
      '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_a1">' +
      "<saml:Issuer>idp</saml:Issuer></saml:Assertion></samlp:Response>";

    function sign(xml: string, xpath: string, location: ComputeSignatureOptionsLocation) {
      const sig = new SignedXml({
        privateKey: fs.readFileSync("./test/static/client.pem"),
        canonicalizationAlgorithm: c14n,
        signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      });
      sig.addReference({
        xpath,
        transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", c14n],
        digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      });
      sig.computeSignature(xml, { prefix: "ds", location });
      return sig.getSignedXml();
    }

    function signAssertion() {
      return sign(unsigned, "//*[local-name(.)='Assertion']", {
        reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']",
        action: "after",
      });
    }

    function checkEachSignature(xml: string) {
      const doc = new xmldom.DOMParser().parseFromString(xml);
      return new SignedXml().findSignatures(doc).map((signature) => {
        const verifier = new SignedXml({
          publicCert: fs.readFileSync("./test/static/client_public.pem"),
        });
        verifier.loadSignature(signature);
        return verifier.checkSignature(xml);
      });
    }

    it("verifies a signature whose SignedInfo is not the first in the document", function () {
      const signed = sign(signAssertion(), "/*", {
        reference: "/*/*[local-name(.)='Issuer']",
        action: "after",
      });

      expect(checkEachSignature(signed)).to.deep.equal([true, true]);
    });

    it("signs SignedInfo with the namespaces in scope of its own Signature", function () {
      const signed = sign(signAssertion(), "/*", { reference: "/*", action: "append" });

      const doc = new xmldom.DOMParser().parseFromString(signed);
      const responseSignature = xpath.select1("/*/*[local-name(.)='Signature']", doc);
      isDomNode.assertIsElementNode(responseSignature);
      const signedInfo = xpath.select1("./*[local-name(.)='SignedInfo']", responseSignature);
      const signatureValue = xpath.select1(
        "string(./*[local-name(.)='SignatureValue'])",
        responseSignature,
      );
      isDomNode.assertIsNodeLike(signedInfo);
      expect(signatureValue).to.be.a("string");

      const canonicalSignedInfo = new C14nCanonicalization().process(signedInfo, {
        ancestorNamespaces: [
          { prefix: "samlp", namespaceURI: samlp },
          { prefix: "saml", namespaceURI: saml },
        ],
      });
      expect(
        crypto.verify(
          "sha256",
          Buffer.from(canonicalSignedInfo),
          fs.readFileSync("./test/static/client_public.pem"),
          Buffer.from(String(signatureValue), "base64"),
        ),
        "SignatureValue must cover SignedInfo without the Assertion's xmlns:xs",
      ).to.be.true;
      expect(checkEachSignature(signed)).to.deep.equal([true, true]);
    });
  });
});
