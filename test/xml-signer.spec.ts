import * as fs from "fs";
import { expect } from "chai";
import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as isDomNode from "@xmldom/is-dom-node";
import {
  XmlSigner,
  XmlSignerFactory,
  type SigningReference,
  type XmlSignerFactoryOptions,
  type ReferenceAttributes,
} from "../src/xml-signer";
import { SignedXml } from "../src";

const privateKey = fs.readFileSync("./test/static/client.pem", "utf-8");
const publicCert = fs.readFileSync("./test/static/client_public.pem", "utf-8");

describe("XmlSignerFactory", function () {
  describe("constructor", function () {
    it("should require signatureAlgorithm", function () {
      expect(() => {
        new XmlSignerFactory({} as XmlSignerFactoryOptions);
      }).to.throw("signatureAlgorithm is required for XmlSignerFactory");
    });

    it("should require canonicalizationAlgorithm", function () {
      expect(() => {
        new XmlSignerFactory({
          signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        } as XmlSignerFactoryOptions);
      }).to.throw("canonicalizationAlgorithm is required for XmlSignerFactory");
    });

    it("should create factory with minimal options", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      expect(factory).to.be.instanceOf(XmlSignerFactory);
    });

    it("should create factory with all options", function () {
      const factory = new XmlSignerFactory({
        privateKey,
        signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        prefix: "ds",
        attributes: { Id: "sig1" },
        inclusiveNamespacesPrefixList: ["ns1", "ns2"],
        keyInfo: {
          content: () => "<custom>keyinfo</custom>",
          attributes: { Id: "keyinfo1" },
        },
        objects: [{ content: "test", attributes: { Id: "obj1" } }],
        references: [
          {
            xpath: "//*[@id='test']",
            transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
            digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
          },
        ],
      });
      expect(factory).to.be.instanceOf(XmlSignerFactory);
    });
  });

  describe("createSigner", function () {
    it("should create signer with provided private key", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });

      const signer = factory.createSigner(privateKey);
      expect(signer).to.be.instanceOf(XmlSigner);
    });

    it("should create signer with factory default private key", function () {
      const factory = new XmlSignerFactory({
        privateKey,
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });

      const signer = factory.createSigner();
      expect(signer).to.be.instanceOf(XmlSigner);
    });

    it("should throw error when no private key is available", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });

      expect(() => factory.createSigner()).to.throw(
        "privateKey is required to create an XmlSigner",
      );
    });

    it("should create signer with default references", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        references: [
          {
            xpath: "//*[@id='test1']",
            transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
            digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
          },
          {
            xpath: "//*[@id='test2']",
            transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
            digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
          },
        ],
      });

      const signer = factory.createSigner(privateKey);
      const xml = '<root><test id="test1">content1</test><test id="test2">content2</test></root>';

      // Should be able to sign without adding references (uses factory defaults)
      expect(() => signer.sign(xml)).to.not.throw();
    });
  });
});

describe("XmlSigner", function () {
  describe("addReference", function () {
    it("should add a signing reference", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      const signer = factory.createSigner(privateKey);
      const reference: SigningReference = {
        xpath: "//*[@id='test']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      };

      expect(() => signer.addReference(reference)).to.not.throw();
    });

    it("should add reference with all optional properties", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      const signer = factory.createSigner(privateKey);
      const reference: SigningReference = {
        xpath: "//*[@id='test']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        inclusiveNamespacesPrefixList: ["ns1", "ns2"],
        attributes: { Id: "ref1", Type: "http://www.w3.org/2000/09/xmldsig#Object" },
      };

      expect(() => signer.addReference(reference)).to.not.throw();
    });

    it("should add multiple references", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        xpath: "//*[@id='test1']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      signer.addReference({
        xpath: "//*[@id='test2']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      expect(() => {
        const xml = '<root><test id="test1">content1</test><test id="test2">content2</test></root>';
        signer.sign(xml);
      }).to.not.throw();
    });

    it("should add URI and XPath references together", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      const signer = factory.createSigner(privateKey);

      // Add XPath reference
      signer.addReference({
        xpath: "//*[@id='test1']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      // Add URI reference (will be converted to XPath internally)
      signer.addReference({
        uri: "#test2",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      expect(() => {
        const xml = '<root><test id="test1">content1</test><test id="test2">content2</test></root>';
        signer.sign(xml);
      }).to.not.throw();
    });

    it("should throw error for external URI references", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      const signer = factory.createSigner(privateKey);

      expect(() => {
        signer.addReference({
          uri: "http://example.com/document.xml",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        });
      }).to.throw(
        "External URI references are not supported for signing: http://example.com/document.xml",
      );
    });

    it("should throw error when URI is specified in attributes", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      const signer = factory.createSigner(privateKey);

      expect(() => {
        signer.addReference({
          uri: "#test",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
          attributes: { URI: "#different-test" } as ReferenceAttributes, // This should be rejected
        });
      }).to.throw("URI must be specified on the reference configuration, not in attributes");
    });

    it("should throw error when adding references after signing", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        xpath: "//*[@id='test']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      const xml = '<root><test id="test">content</test></root>';
      signer.sign(xml);

      expect(() => {
        signer.addReference({
          xpath: "//*[@id='test2']",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        });
      }).to.throw(
        "Cannot add references after signing has been performed. Create a new XmlSigner instance to add more references.",
      );
    });
  });

  describe("sign (synchronous)", function () {
    it("should sign XML with single reference", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        xpath: "//*[@id='test']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      const xml = '<root><test id="test">content</test></root>';
      const signedXml = signer.sign(xml);

      expect(signedXml).to.be.a("string");
      expect(signedXml).to.include("Signature");
      expect(signedXml).to.include("SignedInfo");
      expect(signedXml).to.include("SignatureValue");
    });

    it("should sign XML with multiple references", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        xpath: "//*[@id='test1']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      signer.addReference({
        xpath: "//*[@id='test2']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      const xml = '<root><test id="test1">content1</test><test id="test2">content2</test></root>';
      const signedXml = signer.sign(xml);

      const doc = new xmldom.DOMParser().parseFromString(signedXml);
      const references = xpath.select("//*[local-name(.)='Reference']", doc);
      isDomNode.assertIsArrayOfNodes(references);
      expect(references.length).to.equal(2);
    });

    it("should sign with factory prefix and attributes", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        prefix: "ds",
        attributes: { Id: "sig1" },
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        xpath: "//*[@id='test']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      const xml = '<root><test id="test">content</test></root>';
      const signedXml = signer.sign(xml);

      expect(signedXml).to.include("ds:Signature");
      expect(signedXml).to.include('Id="sig1"');
    });

    it("should sign with empty URI reference (enveloped signature)", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        uri: "",
        transforms: [
          "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
          "http://www.w3.org/2001/10/xml-exc-c14n#",
        ],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      const xml = "<root><test>content</test></root>";
      const signedXml = signer.sign(xml);

      const doc = new xmldom.DOMParser().parseFromString(signedXml);
      const uriAttr = xpath.select1("//*[local-name(.)='Reference']/@URI", doc);
      isDomNode.assertIsAttributeNode(uriAttr);
      expect(uriAttr.value).to.equal("");
    });

    it("should sign with specific URI reference", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        uri: "#test",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      const xml = '<root><test id="test">content</test></root>';
      const signedXml = signer.sign(xml);

      const doc = new xmldom.DOMParser().parseFromString(signedXml);
      const uriAttr = xpath.select1("//*[local-name(.)='Reference']/@URI", doc);
      isDomNode.assertIsAttributeNode(uriAttr);
      expect(uriAttr.value).to.equal("#test");
    });

    it("should include custom KeyInfo content with proper prefix handling", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        keyInfo: {
          content: (args) => {
            const prefix = args?.prefix;
            const ns = prefix ? `${prefix}:` : "";
            return `<${ns}X509Data><${ns}X509Certificate>test-cert</${ns}X509Certificate></${ns}X509Data>`;
          },
        },
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        xpath: "//*[@id='test']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      const xml = '<root><test id="test">content</test></root>';
      const signedXml = signer.sign(xml);

      expect(signedXml).to.include(
        "<X509Data><X509Certificate>test-cert</X509Certificate></X509Data>",
      );
    });

    it("should include custom KeyInfo content with prefix when signature uses prefix", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        prefix: "ds",
        keyInfo: {
          content: (args) => {
            const prefix = args?.prefix;
            const ns = prefix ? `${prefix}:` : "";
            return `<${ns}X509Data><${ns}X509Certificate>test-cert</${ns}X509Certificate></${ns}X509Data>`;
          },
        },
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        xpath: "//*[@id='test']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      const xml = '<root><test id="test">content</test></root>';
      const signedXml = signer.sign(xml);

      expect(signedXml).to.include(
        "<ds:X509Data><ds:X509Certificate>test-cert</ds:X509Certificate></ds:X509Data>",
      );
    });

    it("should include KeyInfo attributes", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        keyInfo: {
          content: () => "<custom>keyinfo</custom>",
          attributes: { Id: "keyinfo1", CustomAttr: "value", AnotherAttr: "test" },
        },
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        xpath: "//*[@id='test']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      const xml = '<root><test id="test">content</test></root>';
      const signedXml = signer.sign(xml);

      const doc = new xmldom.DOMParser().parseFromString(signedXml);
      const keyInfoEl = xpath.select1("//*[local-name(.)='KeyInfo']", doc);
      isDomNode.assertIsElementNode(keyInfoEl);
      expect(keyInfoEl.getAttribute("Id")).to.equal("keyinfo1");
      expect(keyInfoEl.getAttribute("CustomAttr")).to.equal("value");
      expect(keyInfoEl.getAttribute("AnotherAttr")).to.equal("test");
    });

    it("should include Reference attributes", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        xpath: "//*[@id='test']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        attributes: { Id: "ref1", Type: "http://www.w3.org/2000/09/xmldsig#Object" },
      });

      const xml = '<root><test id="test">content</test></root>';
      const signedXml = signer.sign(xml);

      const doc = new xmldom.DOMParser().parseFromString(signedXml);
      const referenceEl = xpath.select1("//*[local-name(.)='Reference']", doc);
      isDomNode.assertIsElementNode(referenceEl);
      expect(referenceEl.getAttribute("Id")).to.equal("ref1");
      expect(referenceEl.getAttribute("Type")).to.equal("http://www.w3.org/2000/09/xmldsig#Object");
    });

    it("should include Object elements", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        objects: [
          {
            content: "<Data>Test data</Data>",
            attributes: { Id: "obj1", MimeType: "text/xml" },
          },
        ],
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        xpath: "//*[@id='test']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      const xml = '<root><test id="test">content</test></root>';
      const signedXml = signer.sign(xml);

      const doc = new xmldom.DOMParser().parseFromString(signedXml);
      const objectEl = xpath.select1("//*[local-name(.)='Object'][@Id='obj1']", doc);
      isDomNode.assertIsElementNode(objectEl);
      expect(objectEl.getAttribute("MimeType")).to.equal("text/xml");
      expect(objectEl.textContent).to.include("Test data");
    });

    it("should handle inclusive namespace prefix lists", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        inclusiveNamespacesPrefixList: ["ns1", "ns2"],
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        xpath: "//*[@id='test']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        inclusiveNamespacesPrefixList: ["ns3", "ns4"],
      });

      const xml =
        '<root xmlns:ns1="uri1" xmlns:ns2="uri2"><test id="test" xmlns:ns3="uri3" xmlns:ns4="uri4">content</test></root>';
      const signedXml = signer.sign(xml);

      const doc = new xmldom.DOMParser().parseFromString(signedXml);

      // Check canonicalization method inclusive namespaces
      const canonInclusiveNs = xpath.select1(
        "//*[local-name(.)='CanonicalizationMethod']/*[local-name(.)='InclusiveNamespaces']",
        doc,
      );
      isDomNode.assertIsElementNode(canonInclusiveNs);
      expect(canonInclusiveNs.getAttribute("PrefixList")).to.equal("ns1 ns2");

      // Check reference transform inclusive namespaces
      const refInclusiveNs = xpath.select1(
        "//*[local-name(.)='Reference']/*[local-name(.)='Transforms']/*[local-name(.)='Transform']/*[local-name(.)='InclusiveNamespaces']",
        doc,
      );
      isDomNode.assertIsElementNode(refInclusiveNs);
      expect(refInclusiveNs.getAttribute("PrefixList")).to.equal("ns3 ns4");
    });

    it("should throw error when xpath matches no nodes", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        xpath: "//*[@id='nonexistent']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      const xml = '<root><test id="test">content</test></root>';

      expect(() => signer.sign(xml)).to.throw(
        /the following xpath cannot be signed because it was not found/,
      );
    });
  });

  describe("sign (asynchronous)", function () {
    it("should sign XML asynchronously with callback", function (done) {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        xpath: "//*[@id='test']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      const xml = '<root><test id="test">content</test></root>';

      signer.sign(xml, (err, signedXml) => {
        try {
          expect(err).to.be.null;
          expect(signedXml).to.be.a("string");
          expect(signedXml).to.include("Signature");
          done();
        } catch (error) {
          done(error);
        }
      });
    });

    it("should sign XML asynchronously with factory prefix", function (done) {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        prefix: "ds",
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        xpath: "//*[@id='test']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      const xml = '<root><test id="test">content</test></root>';

      signer.sign(xml, (err, signedXml) => {
        try {
          expect(err).to.be.null;
          expect(signedXml).to.be.a("string");
          expect(signedXml).to.include("ds:Signature");
          done();
        } catch (error) {
          done(error);
        }
      });
    });

    it("should handle errors in async signing", function (done) {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        xpath: "//*[@id='nonexistent']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      const xml = '<root><test id="test">content</test></root>';

      signer.sign(xml, (err, signedXml) => {
        try {
          expect(err).to.be.instanceOf(Error);
          expect(err?.message).to.include(
            "the following xpath cannot be signed because it was not found",
          );
          expect(signedXml).to.be.undefined;
          done();
        } catch (error) {
          done(error);
        }
      });
    });
  });

  describe("getSignatureXml", function () {
    it("should return signature XML after signing", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        xpath: "//*[@id='test']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      const xml = '<root><test id="test">content</test></root>';
      signer.sign(xml);

      const signatureXml = signer.getSignatureXml();
      expect(signatureXml).to.be.a("string");
      expect(signatureXml).to.include("<Signature");
      expect(signatureXml).to.include("</Signature>");
      expect(signatureXml).to.not.include("<root>");
    });

    it("should throw error when called before signing", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        xpath: "//*[@id='test']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      expect(() => signer.getSignatureXml()).to.throw(
        "Cannot get signature XML before signing a document. Call sign() first.",
      );
    });
  });

  describe("single-use enforcement", function () {
    it("should throw error when trying to sign multiple documents", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        xpath: "//*[@id='test']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      const xml1 = '<root><test id="test">content1</test></root>';
      const xml2 = '<root><test id="test">content2</test></root>';

      // First signing should work
      signer.sign(xml1);

      // Second signing should throw error
      expect(() => signer.sign(xml2)).to.throw(
        "This XmlSigner instance has already been used to sign a document. Create a new instance to sign another document.",
      );
    });

    it("should throw error when trying to sign multiple documents asynchronously", function (done) {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        xpath: "//*[@id='test']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      const xml1 = '<root><test id="test">content1</test></root>';
      const xml2 = '<root><test id="test">content2</test></root>';

      // First signing should work
      signer.sign(xml1, (err, result) => {
        try {
          expect(err).to.be.null;
          expect(result).to.be.a("string");

          // Second signing should throw error
          expect(() => signer.sign(xml2, () => {})).to.throw(
            "This XmlSigner instance has already been used to sign a document. Create a new instance to sign another document.",
          );
          done();
        } catch (error) {
          done(error);
        }
      });
    });
  });

  describe("different signature algorithms", function () {
    const algorithms = [
      "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
    ];

    algorithms.forEach((algorithm) => {
      it(`should sign with ${algorithm}`, function () {
        const factory = new XmlSignerFactory({
          signatureAlgorithm: algorithm,
          canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        });
        const signer = factory.createSigner(privateKey);

        signer.addReference({
          xpath: "//*[@id='test']",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        });

        const xml = '<root><test id="test">content</test></root>';
        const signedXml = signer.sign(xml);

        const doc = new xmldom.DOMParser().parseFromString(signedXml);
        const signatureMethod = xpath.select1("//*[local-name(.)='SignatureMethod']", doc);
        isDomNode.assertIsElementNode(signatureMethod);
        expect(signatureMethod.getAttribute("Algorithm")).to.equal(algorithm);
      });
    });
  });

  describe("different canonicalization algorithms", function () {
    const algorithms = [
      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
      "http://www.w3.org/2001/10/xml-exc-c14n#",
      "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
    ];

    algorithms.forEach((algorithm) => {
      it(`should sign with ${algorithm}`, function () {
        const factory = new XmlSignerFactory({
          signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
          canonicalizationAlgorithm: algorithm,
        });
        const signer = factory.createSigner(privateKey);

        signer.addReference({
          xpath: "//*[@id='test']",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        });

        const xml = '<root><test id="test">content</test></root>';
        const signedXml = signer.sign(xml);

        const doc = new xmldom.DOMParser().parseFromString(signedXml);
        const canonMethod = xpath.select1("//*[local-name(.)='CanonicalizationMethod']", doc);
        isDomNode.assertIsElementNode(canonMethod);
        expect(canonMethod.getAttribute("Algorithm")).to.equal(algorithm);
      });
    });
  });

  describe("different digest algorithms", function () {
    const algorithms = [
      "http://www.w3.org/2000/09/xmldsig#sha1",
      "http://www.w3.org/2001/04/xmlenc#sha256",
      "http://www.w3.org/2001/04/xmlenc#sha512",
    ];

    algorithms.forEach((algorithm) => {
      it(`should sign with ${algorithm}`, function () {
        const factory = new XmlSignerFactory({
          signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
          canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        });
        const signer = factory.createSigner(privateKey);

        signer.addReference({
          xpath: "//*[@id='test']",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: algorithm,
        });

        const xml = '<root><test id="test">content</test></root>';
        const signedXml = signer.sign(xml);

        const doc = new xmldom.DOMParser().parseFromString(signedXml);
        const digestMethod = xpath.select1("//*[local-name(.)='DigestMethod']", doc);
        isDomNode.assertIsElementNode(digestMethod);
        expect(digestMethod.getAttribute("Algorithm")).to.equal(algorithm);
      });
    });
  });

  describe("integration with existing SignedXml functionality", function () {
    it("should produce signatures compatible with SignedXml verification", function () {
      const factory = new XmlSignerFactory({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        keyInfo: {
          content: (args) => {
            const prefix = args?.prefix;
            const ns = prefix ? `${prefix}:` : "";
            // Extract certificate content for KeyInfo
            const certContent = publicCert
              .replace(/-----BEGIN CERTIFICATE-----/, "")
              .replace(/-----END CERTIFICATE-----/, "")
              .replace(/\n/g, "");
            return `<${ns}X509Data><${ns}X509Certificate>${certContent}</${ns}X509Certificate></${ns}X509Data>`;
          },
        },
      });
      const signer = factory.createSigner(privateKey);

      signer.addReference({
        xpath: "//*[@id='test']",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      });

      const xml = '<root><test id="test">content</test></root>';
      const signedXml = signer.sign(xml);

      // Verify the signature can be loaded and validated by SignedXml
      const doc = new xmldom.DOMParser().parseFromString(signedXml);
      const signatureNode = xpath.select1(
        "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
        doc,
      );
      isDomNode.assertIsNodeLike(signatureNode);

      const verifier = new SignedXml();
      verifier.publicCert = publicCert;
      verifier.loadSignature(signatureNode);
      const isValid = verifier.checkSignature(signedXml);

      expect(isValid).to.be.true;
    });
  });
});
