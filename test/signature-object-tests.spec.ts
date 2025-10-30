import * as fs from "fs";
import { expect, assert } from "chai";
import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as isDomNode from "@xmldom/is-dom-node";
import { SignedXml, XMLDSIG_URIS } from "../src";
import { Sha256 } from "../src/hash-algorithms";

const privateKey = fs.readFileSync("./test/static/client.pem", "utf-8");
const publicCert = fs.readFileSync("./test/static/client_public.pem", "utf-8");
const publicCertDer = fs.readFileSync("./test/static/client_public.der");
const selectNs = (expression: string, node: Node, ns?: Record<string, string>) =>
  xpath.useNamespaces({
    ds: XMLDSIG_URIS.NAMESPACES.ds,
    xades: "http://uri.etsi.org/01903/v1.3.2#",
    ...ns,
  })(expression, node, false);
const select1Ns = (expression: string, node: Node, ns?: Record<string, string>) =>
  xpath.useNamespaces({
    ds: XMLDSIG_URIS.NAMESPACES.ds,
    xades: "http://uri.etsi.org/01903/v1.3.2#",
    ...ns,
  })(expression, node, true);

const checkSignature = (signedXml: string, signedDoc: Document) => {
  const verifier = new SignedXml({ publicCert });
  const signatureNode = select1Ns("//ds:Signature", signedDoc);
  isDomNode.assertIsNodeLike(signatureNode);
  verifier.loadSignature(signatureNode);
  const valid = verifier.checkSignature(signedXml);

  return {
    valid,
    errorMessage: verifier
      .getReferences()
      .flatMap((ref) => ref.validationError?.message || [])
      .join(", "),
  };
};

describe("ds:Object support in XML signatures", function () {
  it("should add custom ds:Object elements with attributes to the signature", function () {
    const xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';

    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      signatureAlgorithm: XMLDSIG_URIS.SIGNATURE_ALGORITHMS.RSA_SHA1,
      objects: [
        {
          content: "<Data>Test data in Object element</Data>",
          attributes: {
            Id: "object1",
            MimeType: "text/xml",
            Encoding: "",
          },
        },
        {
          content: "Plain text content",
          attributes: {
            Id: "object2",
            MimeType: "text/plain",
          },
        },
        {
          content: Buffer.from("This is base64 encoded data").toString("base64"),
          attributes: {
            Id: "object3",
            MimeType: "text/plain",
            Encoding: "http://www.w3.org/2000/09/xmldsig#base64",
          },
        },
      ],
    });

    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: XMLDSIG_URIS.HASH_ALGORITHMS.SHA1,
      transforms: [XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();
    const doc = new xmldom.DOMParser().parseFromString(signedXml);

    // Should have three Object elements
    const objectNodes = selectNs("/root/ds:Signature/ds:Object", doc);
    isDomNode.assertIsArrayOfNodes(objectNodes);
    expect(objectNodes.length).to.equal(3);

    // Verify the first Object element
    const object1 = objectNodes[0];
    isDomNode.assertIsElementNode(object1);
    expect(object1.getAttribute("Id")).to.equal("object1");
    expect(object1.getAttribute("MimeType")).to.equal("text/xml");
    expect(object1.hasAttribute("Encoding")).to.be.true;
    expect(object1.getAttribute("Encoding")).to.equal("");
    const object1Data = select1Ns("ds:Data", object1);
    isDomNode.assertIsElementNode(object1Data);
    expect(object1Data.textContent).to.equal("Test data in Object element");

    // Verify the second Object element
    const object2 = objectNodes[1];
    isDomNode.assertIsElementNode(object2);
    expect(object2.getAttribute("Id")).to.equal("object2");
    expect(object2.getAttribute("MimeType")).to.equal("text/plain");
    expect(object2.hasAttribute("Encoding")).to.be.false;
    expect(object2.textContent).to.equal("Plain text content");

    // Verify the third Object element
    const object3 = objectNodes[2];
    isDomNode.assertIsElementNode(object3);
    expect(object3.getAttribute("Id")).to.equal("object3");
    expect(object3.getAttribute("MimeType")).to.equal("text/plain");
    expect(object3.getAttribute("Encoding")).to.equal("http://www.w3.org/2000/09/xmldsig#base64");
    assert(object3.textContent);
    expect(Buffer.from(object3.textContent, "base64").toString("utf-8")).to.equal(
      "This is base64 encoded data",
    );
  });

  it("should have correct ds:Object namespace when there is no default namespace", function () {
    const xml = "<root></root>";

    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      signatureAlgorithm: XMLDSIG_URIS.SIGNATURE_ALGORITHMS.RSA_SHA1,
      objects: [
        {
          content: "Test data",
          attributes: {
            Id: "object1",
            MimeType: "text/plain",
          },
        },
      ],
    });

    sig.addReference({
      xpath: "/*",
      digestAlgorithm: XMLDSIG_URIS.HASH_ALGORITHMS.SHA1,
      transforms: [XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    // When we add a prefix to the signature, there is no default namespace
    sig.computeSignature(xml, { prefix: "ds" });
    const signedXml = sig.getSignedXml();
    const doc = new xmldom.DOMParser().parseFromString(signedXml);

    // Verify the namespace of the ds:Object element
    const objectNode = select1Ns("/root/ds:Signature/ds:Object[@Id='object1']", doc);
    isDomNode.assertIsElementNode(objectNode);
  });

  it("should handle empty or undefined objects", function () {
    const xml = "<root></root>";

    // Test with undefined objects
    const sigWithNull = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      signatureAlgorithm: XMLDSIG_URIS.SIGNATURE_ALGORITHMS.RSA_SHA1,
      objects: undefined,
    });

    sigWithNull.addReference({
      xpath: "/*",
      digestAlgorithm: XMLDSIG_URIS.HASH_ALGORITHMS.SHA1,
      transforms: [XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    sigWithNull.computeSignature(xml);
    const signedXmlWithNull = sigWithNull.getSignedXml();
    const docWithNull = new xmldom.DOMParser().parseFromString(signedXmlWithNull);

    // Verify that no Object elements exist
    const objectNodesWithNull = selectNs("//ds:Object", docWithNull);
    isDomNode.assertIsArrayOfNodes(objectNodesWithNull);
    expect(objectNodesWithNull.length).to.equal(0);

    // Test with empty array objects
    const sigWithEmpty = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      signatureAlgorithm: XMLDSIG_URIS.SIGNATURE_ALGORITHMS.RSA_SHA1,
      objects: [],
    });

    sigWithEmpty.addReference({
      xpath: "/*",
      digestAlgorithm: XMLDSIG_URIS.HASH_ALGORITHMS.SHA1,
      transforms: [XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    sigWithEmpty.computeSignature(xml);
    const signedXmlWithEmpty = sigWithEmpty.getSignedXml();
    const docWithEmpty = new xmldom.DOMParser().parseFromString(signedXmlWithEmpty);

    // Verify that no Object elements exist
    const objectNodesWithEmpty = selectNs("//ds:Object", docWithEmpty);
    isDomNode.assertIsArrayOfNodes(objectNodesWithEmpty);
    expect(objectNodesWithEmpty.length).to.equal(0);
  });

  it("should handle Reference to Object", function () {
    const xml = "<root></root>";

    const sig = new SignedXml({
      privateKey: privateKey,
      signatureAlgorithm: XMLDSIG_URIS.SIGNATURE_ALGORITHMS.RSA_SHA1,
      canonicalizationAlgorithm: XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      objects: [
        {
          content:
            "<Test xmlns:ns1='http://example.com/ns1' xmlns:ns2='http://example.com/ns2'>Content</Test>",
          attributes: {
            Id: "object1",
          },
        },
      ],
    });

    sig.addReference({
      xpath: "//*[local-name(.)='Object' and @Id='object1']",
      inclusiveNamespacesPrefixList: ["ns1", "ns2"],
      digestAlgorithm: XMLDSIG_URIS.HASH_ALGORITHMS.SHA1,
      transforms: [XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();
    const signedDoc = new xmldom.DOMParser().parseFromString(signedXml);

    // Verify that there is exactly one ds:Reference
    const referenceNodes = selectNs("/root/ds:Signature/ds:SignedInfo/ds:Reference", signedDoc);
    isDomNode.assertIsArrayOfNodes(referenceNodes);
    expect(referenceNodes.length).to.equal(1);
    const referenceEl = referenceNodes[0];
    isDomNode.assertIsElementNode(referenceEl);

    // Verify that the Reference URI points to the Object
    expect(referenceEl.getAttribute("URI")).to.equal("#object1");

    // Verify that the Reference contains the correct Transform
    const transformEl = select1Ns("ds:Transforms/ds:Transform", referenceEl);
    isDomNode.assertIsElementNode(transformEl);
    expect(transformEl.getAttribute("Algorithm")).to.equal(
      XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
    );

    // Verify that the InclusiveNamespacesPrefixList is set correctly
    const inclusiveNamespacesEl = select1Ns("ec:InclusiveNamespaces", transformEl, {
      ec: XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
    });
    isDomNode.assertIsElementNode(inclusiveNamespacesEl);
    expect(inclusiveNamespacesEl.getAttribute("PrefixList")).to.equal("ns1 ns2");

    // Verify that the Reference contains the correct DigestMethod
    const digestMethodEl = select1Ns("ds:DigestMethod", referenceEl);
    isDomNode.assertIsElementNode(digestMethodEl);
    expect(digestMethodEl.getAttribute("Algorithm")).to.equal(XMLDSIG_URIS.HASH_ALGORITHMS.SHA1);

    // Verify that the Reference contains a non-empty DigestValue
    const digestValueEl = select1Ns("ds:DigestValue", referenceEl);
    isDomNode.assertIsElementNode(digestValueEl);
    expect(digestValueEl.textContent).to.not.be.empty;
  });
});

describe("Valid signatures with ds:Object elements", function () {
  it("should create valid signatures with NO references to ds:Object", function () {
    const xml = "<root></root>";

    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      signatureAlgorithm: XMLDSIG_URIS.SIGNATURE_ALGORITHMS.RSA_SHA1,
      objects: [
        {
          content: "<Data>Test data in Object element</Data>",
          attributes: {
            Id: "object1",
            MimeType: "text/xml",
          },
        },
      ],
    });

    sig.addReference({
      xpath: "/*",
      digestAlgorithm: XMLDSIG_URIS.HASH_ALGORITHMS.SHA1,
      transforms: [
        XMLDSIG_URIS.TRANSFORM_ALGORITHMS.ENVELOPED_SIGNATURE,
        XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      ],
    });

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();
    const doc = new xmldom.DOMParser().parseFromString(signedXml);

    // Verify that the signature is valid
    const { valid, errorMessage } = checkSignature(signedXml, doc);
    expect(valid, errorMessage).to.be.true;
  });

  it("should create valid signatures with references to ds:Object", () => {
    const xml = '<ns1:root xmlns:ns1="uri:ns1"></ns1:root>';

    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      signatureAlgorithm: XMLDSIG_URIS.SIGNATURE_ALGORITHMS.RSA_SHA1,
      inclusiveNamespacesPrefixList: ["ns1", "ns2"],
      objects: [
        {
          content:
            '<Data xmlns:ns2="uri:ns2" xmlns:ns3="uri:ns3">Test data in Object element</Data>',
          attributes: {
            Id: "object1",
            MimeType: "text/xml",
          },
        },
      ],
    });

    sig.addReference({
      xpath: "/*",
      digestAlgorithm: XMLDSIG_URIS.HASH_ALGORITHMS.SHA1,
      transforms: [
        XMLDSIG_URIS.TRANSFORM_ALGORITHMS.ENVELOPED_SIGNATURE,
        XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      ],
    });

    sig.addReference({
      xpath: "//*[local-name(.)='Object' and @Id='object1']",
      digestAlgorithm: XMLDSIG_URIS.HASH_ALGORITHMS.SHA1,
      transforms: [
        XMLDSIG_URIS.TRANSFORM_ALGORITHMS.ENVELOPED_SIGNATURE,
        XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      ],
      inclusiveNamespacesPrefixList: ["ns1", "ns3"],
    });

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();
    const doc = new xmldom.DOMParser().parseFromString(signedXml);

    // Verify that there are two Reference elements
    const referenceNodes = selectNs("/ns1:root/ds:Signature/ds:SignedInfo/ds:Reference", doc, {
      ns1: "uri:ns1",
    });
    isDomNode.assertIsArrayOfNodes(referenceNodes);
    expect(referenceNodes.length).to.equal(2);

    // Verify that the second Reference points to the ds:Object
    const objectReference = referenceNodes[1];
    isDomNode.assertIsElementNode(objectReference);
    expect(objectReference.getAttribute("URI")).to.equal("#object1");

    // Verify that the signature is valid
    const { valid, errorMessage } = checkSignature(signedXml, doc);
    expect(valid, errorMessage).to.be.true;
  });

  it("should create valid signature and generate Id attribute for ds:Object when not provided", function () {
    const xml = "<root></root>";
    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      signatureAlgorithm: XMLDSIG_URIS.SIGNATURE_ALGORITHMS.RSA_SHA1,
      objects: [
        {
          content: "<Data>Test data in Object element</Data>",
        },
      ],
    });

    sig.addReference({
      xpath: "//*[local-name(.)='Data']",
      digestAlgorithm: XMLDSIG_URIS.HASH_ALGORITHMS.SHA1,
      transforms: [
        XMLDSIG_URIS.TRANSFORM_ALGORITHMS.ENVELOPED_SIGNATURE,
        XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      ],
    });

    sig.computeSignature(xml, { prefix: "ds" });
    const signedXml = sig.getSignedXml();
    const doc = new xmldom.DOMParser().parseFromString(signedXml);

    // Find the ds:Object/Data element and get the value of its Id attribute (ensuring it was generated)
    const dataEl = select1Ns("/root/ds:Signature/ds:Object/Data[@Id]", doc);
    isDomNode.assertIsElementNode(dataEl);
    const idValue = dataEl.getAttribute("Id");
    expect(idValue).to.be.a("string").that.is.not.empty;

    // Verify that there is a Reference pointing to the generated Id
    const uri = `#${idValue}`;
    const refEl = select1Ns(`/root/ds:Signature/ds:SignedInfo/ds:Reference[@URI='${uri}']`, doc);
    isDomNode.assertIsElementNode(refEl);

    // Verify that the signature is valid
    const { valid, errorMessage } = checkSignature(signedXml, doc);
    expect(valid, errorMessage).to.be.true;
  });
});

describe("Should successfuly sign references to ds:KeyInfo elements", function () {
  it("should create valid signatures with references to ds:KeyInfo when the Id attribute is provided", function () {
    const xml = "<root><x /></root>";
    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      signatureAlgorithm: XMLDSIG_URIS.SIGNATURE_ALGORITHMS.RSA_SHA1,
      keyInfoAttributes: {
        Id: "key-info-1",
      },
      getKeyInfoContent: () => "<dummy></dummy>",
    });

    sig.addReference({
      xpath: "//*[local-name(.)='KeyInfo']",
      digestAlgorithm: XMLDSIG_URIS.HASH_ALGORITHMS.SHA1,
      transforms: [
        XMLDSIG_URIS.TRANSFORM_ALGORITHMS.ENVELOPED_SIGNATURE,
        XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      ],
    });

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    const doc = new xmldom.DOMParser().parseFromString(signedXml);

    // Verify that there is a Reference to KeyInfo
    const referenceEl = select1Ns(
      "/root/ds:Signature/ds:SignedInfo/ds:Reference[@URI='#key-info-1']",
      doc,
    );
    isDomNode.assertIsElementNode(referenceEl);

    // Verify that the signature is valid
    const { valid, errorMessage } = checkSignature(signedXml, doc);
    expect(valid, errorMessage).to.be.true;
  });

  it("should create valid signatures with references to ds:KeyInfo when the Id attribute is autogenerated", function () {
    const xml = "<root><x /></root>";
    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      signatureAlgorithm: XMLDSIG_URIS.SIGNATURE_ALGORITHMS.RSA_SHA1,
      getKeyInfoContent: () => "<dummy></dummy>",
    });

    sig.addReference({
      xpath: "//*[local-name(.)='KeyInfo']",
      digestAlgorithm: XMLDSIG_URIS.HASH_ALGORITHMS.SHA1,
      transforms: [
        XMLDSIG_URIS.TRANSFORM_ALGORITHMS.ENVELOPED_SIGNATURE,
        XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      ],
    });

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    const doc = new xmldom.DOMParser().parseFromString(signedXml);

    // Find the KeyInfo element and get the value of its Id attribute (ensuring it was generated)
    const keyInfoEl = select1Ns("/root/ds:Signature/ds:KeyInfo[@Id]", doc);
    isDomNode.assertIsElementNode(keyInfoEl);
    const idValue = keyInfoEl.getAttribute("Id");
    expect(idValue).to.be.a("string").that.is.not.empty;

    // Find a Reference with URI=`#${idValue}`
    const uri = `#${idValue}`;
    const referenceEl = select1Ns(
      `/root/ds:Signature/ds:SignedInfo/ds:Reference[@URI='${uri}']`,
      doc,
    );
    isDomNode.assertIsElementNode(referenceEl);

    // Verify that the signature is valid
    const { valid, errorMessage } = checkSignature(signedXml, doc);
    expect(valid, errorMessage).to.be.true;
  });
});

describe("XAdES Object support in XML signatures", function () {
  it("should be able to add and sign XAdES objects", function () {
    const signatureId = "signature_0";
    const signedPropertiesId = "signedProperties_0";

    const publicCertDigest = new Sha256().getHash(publicCertDer);
    const xml = `<root><content>text</content></root>`;

    const sig = new SignedXml({
      publicCert,
      privateKey,
      canonicalizationAlgorithm: XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      signatureAlgorithm: XMLDSIG_URIS.SIGNATURE_ALGORITHMS.RSA_SHA256,
      objects: [
        {
          content:
            `<xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="#${signatureId}">` +
            `<xades:SignedProperties Id="${signedPropertiesId}">` +
            `<xades:SignedSignatureProperties>` +
            `<xades:SigningTime>2025-06-21T12:00:00Z</xades:SigningTime>` +
            `<xades:SigningCertificateV2><xades:Cert><xades:CertDigest>` +
            `<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
            `<ds:DigestValue>${publicCertDigest}</ds:DigestValue>` +
            `</xades:CertDigest></xades:Cert></xades:SigningCertificateV2>` +
            `</xades:SignedSignatureProperties>` +
            `</xades:SignedProperties>` +
            `</xades:QualifyingProperties>`,
        },
      ],
    });

    sig.addReference({
      xpath: `/*`,
      isEmptyUri: true,
      digestAlgorithm: XMLDSIG_URIS.HASH_ALGORITHMS.SHA256,
      transforms: [
        XMLDSIG_URIS.TRANSFORM_ALGORITHMS.ENVELOPED_SIGNATURE,
        XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      ],
    });

    sig.addReference({
      xpath: `//*[@Id='${signedPropertiesId}']`,
      type: "http://uri.etsi.org/01903#SignedProperties",
      digestAlgorithm: XMLDSIG_URIS.HASH_ALGORITHMS.SHA256,
      transforms: [XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    sig.computeSignature(xml, {
      prefix: "ds",
      location: {
        action: "append",
        reference: "/root",
      },
      attrs: {
        Id: signatureId,
      },
    });

    const signedXml = sig.getSignedXml();
    const signedDoc = new xmldom.DOMParser().parseFromString(signedXml);

    // ds:Signature exists and has the expected Id
    const elSig = select1Ns(`/root/ds:Signature[@Id='${signatureId}']`, signedDoc);
    isDomNode.assertIsElementNode(elSig);

    // ds:Object/xades:QualifyingProperties exists within the signature
    const elQP = select1Ns("ds:Object/xades:QualifyingProperties", elSig);
    isDomNode.assertIsElementNode(elQP);

    // The Reference to SignedProperties exists and has the correct URI and Type
    const elSPRef = select1Ns(
      `ds:SignedInfo/ds:Reference[@URI='#${signedPropertiesId}' and @Type='http://uri.etsi.org/01903#SignedProperties']`,
      elSig,
    );
    isDomNode.assertIsElementNode(elSPRef);

    // Verify that the signature is valid
    const { valid, errorMessage } = checkSignature(signedXml, signedDoc);
    expect(valid, errorMessage).to.be.true;
  });
});

describe("Signature self-reference prevention", function () {
  it("should not allow self-referencing the Signature element", function () {
    const xml = "<root></root>";

    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      signatureAlgorithm: XMLDSIG_URIS.SIGNATURE_ALGORITHMS.RSA_SHA1,
    });

    sig.addReference({
      xpath: ".//*[local-name(.)='Signature']",
      digestAlgorithm: XMLDSIG_URIS.HASH_ALGORITHMS.SHA1,
      transforms: [XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    expect(() => {
      sig.computeSignature(xml);
    }).to.throw(/Cannot sign a reference to the Signature or SignedInfo element itself/);
  });

  it("should not allow self-referencing the SignedInfo element", function () {
    const xml = "<root></root>";

    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      signatureAlgorithm: XMLDSIG_URIS.SIGNATURE_ALGORITHMS.RSA_SHA1,
    });

    sig.addReference({
      xpath: ".//*[local-name(.)='SignedInfo']",
      digestAlgorithm: XMLDSIG_URIS.HASH_ALGORITHMS.SHA1,
      transforms: [XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    expect(() => {
      sig.computeSignature(xml);
    }).to.throw(/Cannot sign a reference to the Signature or SignedInfo element itself/);
  });

  it("should not allow signing children of the SignedInfo element", function () {
    const xml = "<root></root>";

    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      signatureAlgorithm: XMLDSIG_URIS.SIGNATURE_ALGORITHMS.RSA_SHA1,
    });

    sig.addReference({
      xpath: "/*",
      digestAlgorithm: XMLDSIG_URIS.HASH_ALGORITHMS.SHA1,
      transforms: [XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    sig.addReference({
      xpath: ".//*[local-name(.)='Reference']/*",
      digestAlgorithm: XMLDSIG_URIS.HASH_ALGORITHMS.SHA1,
      transforms: [XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    expect(() => {
      sig.computeSignature(xml);
    }).to.throw(/Cannot sign a reference to the Signature or SignedInfo element itself/);
  });
});
