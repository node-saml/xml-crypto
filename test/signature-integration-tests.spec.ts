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
          { name: "creates a verifiable detached signature", reference: "/*", detached: true },
        ]) {
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

            const xml = "<root>trusted</root>";
            if (useCallback) {
              await new Promise<void>((resolve, reject) => {
                signer.computeSignature(xml, (err) => (err ? reject(err) : resolve()));
              });
            } else {
              signer.computeSignature(xml);
            }

            const signedXml = detached
              ? // eslint-disable-next-line deprecation/deprecation
                signer.getOriginalXmlWithIds()
              : signer.getSignedXml();
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
});
