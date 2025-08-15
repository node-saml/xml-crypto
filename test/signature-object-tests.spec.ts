import * as fs from "fs";
import { expect } from "chai";
import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as isDomNode from "@xmldom/is-dom-node";
import { SignedXml } from "../src";
import { Sha256 } from "../src/hash-algorithms";

const privateKey = fs.readFileSync("./test/static/client.pem", "utf-8");
const publicCert = fs.readFileSync("./test/static/client_public.pem", "utf-8");
const publicCertDer = fs.readFileSync("./test/static/client_public.der");

const checkSignature = (signedXml: string, signedDoc?: Document) => {
  if (!signedDoc) {
    signedDoc = new xmldom.DOMParser().parseFromString(signedXml);
  }
  const verifier = new SignedXml({ publicCert });
  const signatureNode = xpath.select1(
    "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    signedDoc,
  );
  isDomNode.assertIsNodeLike(signatureNode);
  verifier.loadSignature(signatureNode);
  return verifier.checkSignature(signedXml);
};

describe("Object support in XML signatures", function () {
  it("should add custom ds:Object elements to signature", function () {
    const xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';

    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
      objects: [
        {
          content: "<Data>Test data in Object element</Data>",
          attributes: {
            Id: "object1",
            MimeType: "text/xml",
          },
        },
        {
          content: "Plain text content",
          attributes: {
            Id: "object2",
            MimeType: "text/plain",
          },
        },
      ],
    });

    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();
    const doc = new xmldom.DOMParser().parseFromString(signedXml);

    // Should have two Object elements
    const objectNodes = xpath.select("//*[local-name(.)='Object']", doc);
    isDomNode.assertIsArrayOfNodes(objectNodes);
    expect(objectNodes.length).to.equal(2);

    // Verify the first Object element
    const firstObject = objectNodes[0];
    isDomNode.assertIsElementNode(firstObject);
    expect(firstObject.getAttribute("Id")).to.equal("object1");
    expect(firstObject.getAttribute("MimeType")).to.equal("text/xml");
    expect(firstObject.textContent?.includes("Test data in Object element")).to.be.true;

    // Verify the second Object element
    const secondObject = objectNodes[1];
    isDomNode.assertIsElementNode(secondObject);
    expect(secondObject.getAttribute("Id")).to.equal("object2");
    expect(secondObject.getAttribute("MimeType")).to.equal("text/plain");
    expect(secondObject.textContent).to.equal("Plain text content");

    // Verify that the signature is valid
    expect(checkSignature(signedXml, doc)).to.be.true;
  });

  it("should handle empty or undefined objects", function () {
    const xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';

    // Test with undefined objects
    const sigWithNull = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
      objects: undefined,
    });

    sigWithNull.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    sigWithNull.computeSignature(xml);
    const signedXmlWithNull = sigWithNull.getSignedXml();
    const docWithNull = new xmldom.DOMParser().parseFromString(signedXmlWithNull);

    // Verify that no Object elements exist
    const objectNodesWithNull = xpath.select("//*[local-name(.)='Object']", docWithNull);
    expect(objectNodesWithNull).to.be.an("array").that.is.empty;

    // Test with empty array objects
    const sigWithEmpty = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
      objects: [],
    });

    sigWithEmpty.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    sigWithEmpty.computeSignature(xml);
    const signedXmlWithEmpty = sigWithEmpty.getSignedXml();
    const docWithEmpty = new xmldom.DOMParser().parseFromString(signedXmlWithEmpty);

    // Verify that no Object elements exist
    const objectNodesWithEmpty = xpath.select("//*[local-name(.)='Object']", docWithEmpty);
    expect(objectNodesWithEmpty).to.be.an("array").that.is.empty;
  });

  it("should handle Object with Encoding attribute", function () {
    const xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';

    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
      objects: [
        {
          content: "VGhpcyBpcyBiYXNlNjQgZW5jb2RlZCBkYXRh", // "This is base64 encoded data"
          attributes: {
            Id: "object1",
            MimeType: "application/octet-stream",
            Encoding: "http://www.w3.org/2000/09/xmldsig#base64",
          },
        },
      ],
    });

    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();
    const signedDoc = new xmldom.DOMParser().parseFromString(signedXml);

    // Verify that the Object element exists
    const objectNodes = xpath.select("//*[local-name(.)='Object']", signedDoc);
    isDomNode.assertIsArrayOfNodes(objectNodes);
    expect(objectNodes.length).to.equal(1);

    // Verify the Object element
    const object = objectNodes[0];
    isDomNode.assertIsElementNode(object);
    expect(object.getAttribute("Id")).to.equal("object1");
    expect(object.getAttribute("MimeType")).to.equal("application/octet-stream");
    expect(object.getAttribute("Encoding")).to.equal("http://www.w3.org/2000/09/xmldsig#base64");
    expect(object.textContent).to.equal("VGhpcyBpcyBiYXNlNjQgZW5jb2RlZCBkYXRh");

    // Verify that the signature is valid
    expect(checkSignature(signedXml, signedDoc)).to.be.true;
  });

  it("should sign Object with SHA256 digest algorithm", function () {
    const xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';

    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      objects: [
        {
          content: "<Data>Test data for SHA256 digest</Data>",
          attributes: {
            Id: "object1",
            MimeType: "text/xml",
          },
        },
      ],
    });

    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    sig.addReference({
      xpath: "//*[@Id='object1']",
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    const doc = new xmldom.DOMParser().parseFromString(signedXml);

    // Verify that the ds:Object element exists
    const objectNodes = xpath.select("//*[local-name(.)='Object']", doc);
    isDomNode.assertIsArrayOfNodes(objectNodes);
    expect(objectNodes.length).to.equal(1);

    // Verify that there are two Reference elements
    const referenceNodes = xpath.select("//*[local-name(.)='Reference']", doc);
    isDomNode.assertIsArrayOfNodes(referenceNodes);
    expect(referenceNodes.length).to.equal(2);

    // Verify that the references use SHA256
    const digestMethodNodes = xpath.select("//*[local-name(.)='DigestMethod']", doc);
    isDomNode.assertIsArrayOfNodes(digestMethodNodes);

    for (const digestMethod of digestMethodNodes) {
      isDomNode.assertIsElementNode(digestMethod);
      expect(digestMethod.getAttribute("Algorithm")).to.equal(
        "http://www.w3.org/2001/04/xmlenc#sha256",
      );
    }

    // Verify that the signature method is RSA-SHA256
    const signatureMethod = xpath.select1("//*[local-name(.)='SignatureMethod']", doc);
    isDomNode.assertIsElementNode(signatureMethod);
    expect(signatureMethod.getAttribute("Algorithm")).to.equal(
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    );

    // Verify that the signature is valid
    expect(checkSignature(signedXml, doc)).to.be.true;
  });

  it("should sign Object with SHA512 digest algorithm and RSA-SHA512 signature", function () {
    const xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';

    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
      objects: [
        {
          content: "<Data>Test data for SHA512 digest</Data>",
          attributes: {
            Id: "object1",
            MimeType: "text/xml",
          },
        },
      ],
    });

    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha512",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    sig.addReference({
      xpath: "//*[@Id='object1']",
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha512",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();
    const doc = new xmldom.DOMParser().parseFromString(signedXml);

    // Verify that the ds:Object element exists
    const objectNodes = xpath.select("//*[local-name(.)='Object']", doc);
    isDomNode.assertIsArrayOfNodes(objectNodes);
    expect(objectNodes.length).to.equal(1);

    // Verify that there are two Reference elements
    const referenceNodes = xpath.select("//*[local-name(.)='Reference']", doc);
    isDomNode.assertIsArrayOfNodes(referenceNodes);
    expect(referenceNodes.length).to.equal(2);

    // Verify that the references use SHA512
    const digestMethodNodes = xpath.select("//*[local-name(.)='DigestMethod']", doc);
    isDomNode.assertIsArrayOfNodes(digestMethodNodes);

    for (const digestMethod of digestMethodNodes) {
      isDomNode.assertIsElementNode(digestMethod);
      expect(digestMethod.getAttribute("Algorithm")).to.equal(
        "http://www.w3.org/2001/04/xmlenc#sha512",
      );
    }

    // Verify that the signature method is RSA-SHA512
    const signatureMethod = xpath.select1("//*[local-name(.)='SignatureMethod']", doc);
    isDomNode.assertIsElementNode(signatureMethod);
    expect(signatureMethod.getAttribute("Algorithm")).to.equal(
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
    );

    // Verify that the signature is valid
    expect(checkSignature(signedXml, doc)).to.be.true;
  });

  it("should sign Object with C14N canonicalization algorithm", function () {
    const xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';

    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
      signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
      objects: [
        {
          content: "<Data>Test data for C14N canonicalization</Data>",
          attributes: {
            Id: "object1",
            MimeType: "text/xml",
          },
        },
      ],
    });

    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/TR/2001/REC-xml-c14n-20010315"],
    });

    sig.addReference({
      xpath: "//*[@Id='object1']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/TR/2001/REC-xml-c14n-20010315"],
    });

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();
    const doc = new xmldom.DOMParser().parseFromString(signedXml);

    // Verify that the ds:Object element exists
    const objectNodes = xpath.select("//*[local-name(.)='Object']", doc);
    isDomNode.assertIsArrayOfNodes(objectNodes);
    expect(objectNodes.length).to.equal(1);

    // Verify that there are two Reference elements
    const referenceNodes = xpath.select("//*[local-name(.)='Reference']", doc);
    isDomNode.assertIsArrayOfNodes(referenceNodes);
    expect(referenceNodes.length).to.equal(2);

    // Verify that the transforms use C14N
    const transforms = xpath.select(
      "//*[local-name(.)='Reference']/*[local-name(.)='Transforms']/*[local-name(.)='Transform']",
      doc,
    );
    isDomNode.assertIsArrayOfNodes(transforms);

    for (const transform of transforms) {
      isDomNode.assertIsElementNode(transform);
      expect(transform.getAttribute("Algorithm")).to.equal(
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
      );
    }

    // Verify that the CanonicalizationMethod is C14N
    const canonMethod = xpath.select1("//*[local-name(.)='CanonicalizationMethod']", doc);
    isDomNode.assertIsElementNode(canonMethod);
    expect(canonMethod.getAttribute("Algorithm")).to.equal(
      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    );

    // Verify that the signature is valid
    expect(checkSignature(signedXml, doc)).to.be.true;
  });

  it("should add a reference to an Object element", function () {
    const xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';

    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
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
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    sig.addReference({
      xpath: "//*[@Id='object1']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();
    const doc = new xmldom.DOMParser().parseFromString(signedXml);

    // Verify that the ds:Object element exists
    const objectNodes = xpath.select("//*[local-name(.)='Object']", doc);
    isDomNode.assertIsArrayOfNodes(objectNodes);
    expect(objectNodes.length).to.equal(1);

    // Verify that there are two Reference elements
    const referenceNodes = xpath.select("//*[local-name(.)='Reference']", doc);
    isDomNode.assertIsArrayOfNodes(referenceNodes);
    expect(referenceNodes.length).to.equal(2);

    // Verify that one of the references points to the Object
    const objectReference = xpath.select("//*[local-name(.)='Reference' and @URI='#object1']", doc);
    isDomNode.assertIsArrayOfNodes(objectReference);
    expect(objectReference.length).to.equal(1);

    // Verify that the reference is actually in the SignedInfo section
    const signedInfoReference = xpath.select(
      "//*[local-name(.)='SignedInfo']/*[local-name(.)='Reference' and @URI='#object1']",
      doc,
    );
    isDomNode.assertIsArrayOfNodes(signedInfoReference);
    expect(signedInfoReference.length).to.equal(1);

    // Verify that the signature is valid
    expect(checkSignature(signedXml, doc)).to.be.true;
  });

  it("should allow signing Object elements within the Signature", function () {
    const xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';

    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
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
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    sig.addReference({
      xpath: "//*[@Id='object1']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();
    const doc = new xmldom.DOMParser().parseFromString(signedXml);

    // Verify that the ds:Object element exists
    const objectNodes = xpath.select("//*[local-name(.)='Object']", doc);
    isDomNode.assertIsArrayOfNodes(objectNodes);
    expect(objectNodes.length).to.equal(1);

    // Verify that there are two Reference elements
    const referenceNodes = xpath.select("//*[local-name(.)='Reference']", doc);
    isDomNode.assertIsArrayOfNodes(referenceNodes);
    expect(referenceNodes.length).to.equal(2);

    // Verify that one of the references points to the Object
    const objectReference = xpath.select("//*[local-name(.)='Reference' and @URI='#object1']", doc);
    isDomNode.assertIsArrayOfNodes(objectReference);
    expect(objectReference.length).to.equal(1);

    // Verify that the signature is valid
    expect(checkSignature(signedXml, doc)).to.be.true;
  });

  it("should handle inclusiveNamespacesPrefixList in object reference", () => {
    const xml = "<root></root>";

    const sig = new SignedXml({
      privateKey: privateKey,
      signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
      canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
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
      xpath: "//*[local-name(.)='Object']",
      inclusiveNamespacesPrefixList: ["ns1", "ns2"],
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    // Verify that the Object element is present
    expect(signedXml).to.include('<InclusiveNamespaces PrefixList="ns1 ns2"');
    // Verify that the Reference URI is correct
    expect(signedXml).to.include('URI="#object1"');

    // Verify that the signature is valid
    expect(checkSignature(signedXml)).to.be.true;
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
      canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
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
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      transforms: [
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        "http://www.w3.org/2001/10/xml-exc-c14n#",
      ],
    });

    sig.addReference({
      xpath: `//*[@Id='${signedPropertiesId}']`,
      type: "http://uri.etsi.org/01903#SignedProperties",
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
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

    // Verify that the signature is valid
    expect(checkSignature(signedXml)).to.be.true;
  });
});
