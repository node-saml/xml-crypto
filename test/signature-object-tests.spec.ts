import * as fs from "fs";
import { expect } from "chai";
import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as isDomNode from "@xmldom/is-dom-node";
import { SignedXml } from "../src";
import { Sha256 } from "../lib/hash-algorithms";

describe("Object support in XML signatures", function () {
  it("should add custom ds:Object elements to signature", function () {
    // Create a simple XML document to sign
    const xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';

    // Create a SignedXml instance with custom objects
    const sig = new SignedXml({
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

    // Set up the signature
    sig.privateKey = fs.readFileSync("./test/static/client.pem");
    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    // Set required algorithms
    sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    // Compute the signature
    sig.computeSignature(xml);

    // Get the signed XML
    const signedXml = sig.getSignedXml();

    // Parse the signed XML
    const doc = new xmldom.DOMParser().parseFromString(signedXml);

    // Verify that the ds:Object elements exist
    const objectNodes = xpath.select("//*[local-name(.)='Object']", doc);
    isDomNode.assertIsArrayOfNodes(objectNodes);

    // Should have two Object elements
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

    // Verify that the signature is still valid
    const verifier = new SignedXml();
    verifier.publicCert = fs.readFileSync("./test/static/client_public.pem");

    // First load the signature
    const signedDoc = new xmldom.DOMParser().parseFromString(signedXml);
    const signatureNode = xpath.select1(
      "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      signedDoc,
    );
    isDomNode.assertIsNodeLike(signatureNode);
    verifier.loadSignature(signatureNode);

    // Then check the signature
    const isValid = verifier.checkSignature(signedXml);
    expect(isValid).to.be.true;
  });

  it("should handle empty or null getObjectContent", function () {
    // Create a simple XML document to sign
    const xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';

    // Test with undefined objects
    const sigWithNull = new SignedXml({
      objects: undefined,
    });

    sigWithNull.privateKey = fs.readFileSync("./test/static/client.pem");
    sigWithNull.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    // Set required algorithms
    sigWithNull.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sigWithNull.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    sigWithNull.computeSignature(xml);
    const signedXmlWithNull = sigWithNull.getSignedXml();

    // Parse the signed XML
    const docWithNull = new xmldom.DOMParser().parseFromString(signedXmlWithNull);

    // Verify that no ds:Object elements exist
    const objectNodesWithNull = xpath.select("//*[local-name(.)='Object']", docWithNull);

    if (Array.isArray(objectNodesWithNull)) {
      expect(objectNodesWithNull.length).to.equal(0);
    } else {
      expect(objectNodesWithNull).to.not.exist;
    }

    // Test with empty array objects
    const sigWithEmpty = new SignedXml({
      objects: [],
    });

    sigWithEmpty.privateKey = fs.readFileSync("./test/static/client.pem");
    sigWithEmpty.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    // Set required algorithms
    sigWithEmpty.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sigWithEmpty.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    sigWithEmpty.computeSignature(xml);
    const signedXmlWithEmpty = sigWithEmpty.getSignedXml();

    // Parse the signed XML
    const docWithEmpty = new xmldom.DOMParser().parseFromString(signedXmlWithEmpty);

    // Verify that no ds:Object elements exist
    const objectNodesWithEmpty = xpath.select("//*[local-name(.)='Object']", docWithEmpty);

    if (Array.isArray(objectNodesWithEmpty)) {
      expect(objectNodesWithEmpty.length).to.equal(0);
    } else {
      expect(objectNodesWithEmpty).to.not.exist;
    }
  });

  it("should handle Object with Encoding attribute", function () {
    // Create a simple XML document to sign
    const xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';

    // Create a SignedXml instance with custom objects including Encoding attribute
    const sig = new SignedXml({
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

    // Set up the signature
    sig.privateKey = fs.readFileSync("./test/static/client.pem");
    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    // Set required algorithms
    sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    // Compute the signature
    sig.computeSignature(xml);

    // Get the signed XML
    const signedXml = sig.getSignedXml();

    // Parse the signed XML
    const signedDoc = new xmldom.DOMParser().parseFromString(signedXml);

    // Verify that the ds:Object element exists
    const objectNodes = xpath.select("//*[local-name(.)='Object']", signedDoc);
    isDomNode.assertIsArrayOfNodes(objectNodes);

    // Should have one Object element
    expect(objectNodes.length).to.equal(1);

    // Verify the Object element
    const object = objectNodes[0];
    isDomNode.assertIsElementNode(object);
    expect(object.getAttribute("Id")).to.equal("object1");
    expect(object.getAttribute("MimeType")).to.equal("application/octet-stream");
    expect(object.getAttribute("Encoding")).to.equal("http://www.w3.org/2000/09/xmldsig#base64");
    expect(object.textContent).to.equal("VGhpcyBpcyBiYXNlNjQgZW5jb2RlZCBkYXRh");

    // Verify that the signature is still valid
    const verifier = new SignedXml();
    verifier.publicCert = fs.readFileSync("./test/static/client_public.pem");

    // First load the signature
    const doc = new xmldom.DOMParser().parseFromString(signedXml);
    const signatureNode = xpath.select1(
      "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signatureNode);
    verifier.loadSignature(signatureNode);

    // Then check the signature
    const isValid = verifier.checkSignature(signedXml);
    expect(isValid).to.be.true;
  });

  it("should sign Object with SHA256 digest algorithm", function () {
    // Create a simple XML document to sign
    const xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';

    // Create a SignedXml instance with custom objects
    const sig = new SignedXml({
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

    // Set up the signature
    sig.privateKey = fs.readFileSync("./test/static/client.pem");

    // Add a reference to the document element
    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    // Add a reference to the Object element with SHA256
    sig.addReference({
      xpath: "//*[@Id='object1']",
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    // Set required algorithms
    sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    // Compute the signature
    sig.computeSignature(xml);

    // Get the signed XML
    const signedXml = sig.getSignedXml();

    // Parse the signed XML
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

    // Verify that the signature is still valid
    const verifier = new SignedXml();
    verifier.publicCert = fs.readFileSync("./test/static/client_public.pem");

    // First load the signature
    const signatureNode = xpath.select1(
      "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signatureNode);
    verifier.loadSignature(signatureNode);

    // Then check the signature
    const isValid = verifier.checkSignature(signedXml);
    expect(isValid).to.be.true;
  });

  it("should sign Object with SHA512 digest algorithm and RSA-SHA512 signature", function () {
    // Create a simple XML document to sign
    const xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';

    // Create a SignedXml instance with custom objects
    const sig = new SignedXml({
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

    // Set up the signature
    sig.privateKey = fs.readFileSync("./test/static/client.pem");

    // Add a reference to the document element
    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha512",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    // Add a reference to the Object element with SHA512
    sig.addReference({
      xpath: "//*[@Id='object1']",
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha512",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    // Set required algorithms
    sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

    // Compute the signature
    sig.computeSignature(xml);

    // Get the signed XML
    const signedXml = sig.getSignedXml();

    // Parse the signed XML
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

    // Verify that the signature is still valid
    const verifier = new SignedXml();
    verifier.publicCert = fs.readFileSync("./test/static/client_public.pem");

    // First load the signature
    const signatureNode = xpath.select1(
      "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signatureNode);
    verifier.loadSignature(signatureNode);

    // Then check the signature
    const isValid = verifier.checkSignature(signedXml);
    expect(isValid).to.be.true;
  });

  it("should sign Object with C14N canonicalization algorithm", function () {
    // Create a simple XML document to sign
    const xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';

    // Create a SignedXml instance with custom objects
    const sig = new SignedXml({
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

    // Set up the signature
    sig.privateKey = fs.readFileSync("./test/static/client.pem");

    // Add a reference to the document element
    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/TR/2001/REC-xml-c14n-20010315"],
    });

    // Add a reference to the Object element
    sig.addReference({
      xpath: "//*[@Id='object1']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/TR/2001/REC-xml-c14n-20010315"],
    });

    // Set required algorithms
    sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    // Compute the signature
    sig.computeSignature(xml);

    // Get the signed XML
    const signedXml = sig.getSignedXml();

    // Parse the signed XML
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

    // Verify that the signature is still valid
    const verifier = new SignedXml();
    verifier.publicCert = fs.readFileSync("./test/static/client_public.pem");

    // First load the signature
    const signatureNode = xpath.select1(
      "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signatureNode);
    verifier.loadSignature(signatureNode);

    // Then check the signature
    const isValid = verifier.checkSignature(signedXml);
    expect(isValid).to.be.true;
  });

  it("should add a reference to an Object element", function () {
    // Create a simple XML document to sign
    const xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';

    // Create a SignedXml instance with custom objects
    const sig = new SignedXml({
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

    // Set up the signature
    sig.privateKey = fs.readFileSync("./test/static/client.pem");

    // Add a reference to the document element
    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    // Add a reference to the Object element by its ID
    sig.addReference({
      xpath: "//*[@Id='object1']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    // Set required algorithms
    sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    // Compute the signature
    sig.computeSignature(xml);

    // Get the signed XML
    const signedXml = sig.getSignedXml();

    // Parse the signed XML
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

    // Verify that the signature is still valid
    const verifier = new SignedXml();
    verifier.publicCert = fs.readFileSync("./test/static/client_public.pem");

    // First load the signature
    const signatureNode = xpath.select1(
      "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signatureNode);
    verifier.loadSignature(signatureNode);

    // Then check the signature
    const isValid = verifier.checkSignature(signedXml);
    expect(isValid).to.be.true;
  });

  it("should allow signing Object elements within the Signature", function () {
    // Create a simple XML document to sign
    const xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';

    // Create a SignedXml instance with custom objects
    const sig = new SignedXml({
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

    // Set up the signature
    sig.privateKey = fs.readFileSync("./test/static/client.pem");

    // Add a reference to the document element
    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    // Add a reference to the Object element by its ID
    sig.addReference({
      xpath: "//*[@Id='object1']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    // Set required algorithms
    sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    // Compute the signature
    sig.computeSignature(xml);

    // Get the signed XML
    const signedXml = sig.getSignedXml();

    // Parse the signed XML
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

    // Verify that the signature is still valid
    const verifier = new SignedXml();
    verifier.publicCert = fs.readFileSync("./test/static/client_public.pem");

    // First load the signature
    const signatureNode = xpath.select1(
      "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signatureNode);
    verifier.loadSignature(signatureNode);

    // Then check the signature
    const isValid = verifier.checkSignature(signedXml);
    expect(isValid).to.be.true;
  });
});

describe("XAdES Object support in XML signatures", function () {
  it("should be able to add and sign XAdES objects", function () {
    const signatureId = "signature_0";
    const signedPropertiesId = "signedProperties_0";

    const privateKey = fs.readFileSync("./test/static/client.pem");
    const publicCert = fs.readFileSync("./test/static/client_public.pem");
    const publicCertDer = fs.readFileSync("./test/static/client_public.der");
    const publicCertDigest = new Sha256().getHash(publicCertDer);
    const xml = `<root><content>text</content></root>`;

    const sig = new SignedXml({
      publicCert: publicCert,
      privateKey: privateKey,
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
    const signedDoc = new xmldom.DOMParser().parseFromString(signedXml);
    const signatureNode = xpath.select1(
      "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      signedDoc,
    );
    isDomNode.assertIsNodeLike(signatureNode);

    const verifier = new SignedXml({
      publicCert: publicCert,
    });
    verifier.loadSignature(signatureNode);
    const isValid = verifier.checkSignature(signedXml);
    expect(isValid).to.be.true;
  });
});
