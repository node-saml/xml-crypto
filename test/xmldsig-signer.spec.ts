import * as fs from "fs";
import { expect } from "chai";
import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as isDomNode from "@xmldom/is-dom-node";
import {
  XmlDSigSigner,
  type SigningReference,
  type ReferenceAttributes,
} from "../src/xmldsig-signer";
import { SignedXml } from "../src";

const privateKey = fs.readFileSync("./test/static/client.pem", "utf-8");
const publicCert = fs.readFileSync("./test/static/client_public.pem", "utf-8");

describe("XmlDSigSigner", function () {
  describe("constructor", function () {
    it("should require signatureAlgorithm", function () {
      expect(() => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new XmlDSigSigner({} as any);
      }).to.throw("signatureAlgorithm is required for XmlDSigSigner");
    });

    it("should require canonicalizationAlgorithm", function () {
      expect(() => {
        new XmlDSigSigner({
          signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } as any);
      }).to.throw("canonicalizationAlgorithm is required for XmlDSigSigner");
    });

    it("should create signer with minimal options", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      expect(signer).to.be.instanceOf(XmlDSigSigner);
    });

    it("should create signer with all options", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        prefix: "ds",
        attributes: { Id: "sig1" },
        inclusiveNamespacesPrefixList: ["ns1", "ns2"],
        keyInfo: {
          getContent: () => "<custom>keyinfo</custom>",
          attributes: { Id: "keyinfo1" },
        },
        objects: [{ content: "test", attributes: { Id: "obj1" } }],
        idAttributes: ["customId", "id", "Id"],
      });
      expect(signer).to.be.instanceOf(XmlDSigSigner);
    });

    it("should use default ID attributes when none provided", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });
      expect(signer).to.be.instanceOf(XmlDSigSigner);
    });
  });

  describe("sign", function () {
    it("should require at least one reference", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });

      const xml = '<root><test id="test">content</test></root>';

      expect(() => {
        signer.sign(xml, privateKey, []);
      }).to.throw("At least one reference is required for signing");
    });

    it("should sign XML with single reference", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });

      const references: SigningReference[] = [
        {
          xpath: "//*[@id='test']",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        },
      ];

      const xml = '<root><test id="test">content</test></root>';
      const result = signer.sign(xml, privateKey, references);

      expect(result.signedDocument).to.be.a("string");
      expect(result.signedDocument).to.include("Signature");
      expect(result.signedDocument).to.include("SignedInfo");
      expect(result.signedDocument).to.include("SignatureValue");
      expect(result.signatureXml).to.be.a("string");
      expect(result.signatureXml).to.include("<Signature");
    });

    it("should sign XML with multiple references", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });

      const references: SigningReference[] = [
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
      ];

      const xml = '<root><test id="test1">content1</test><test id="test2">content2</test></root>';
      const result = signer.sign(xml, privateKey, references);

      const doc = new xmldom.DOMParser().parseFromString(result.signedDocument);
      const referenceNodes = xpath.select("//*[local-name(.)='Reference']", doc);
      isDomNode.assertIsArrayOfNodes(referenceNodes);
      expect(referenceNodes.length).to.equal(2);
    });

    it("should sign with prefix and attributes", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        prefix: "ds",
        attributes: { Id: "sig1" },
      });

      const references: SigningReference[] = [
        {
          xpath: "//*[@id='test']",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        },
      ];

      const xml = '<root><test id="test">content</test></root>';
      const result = signer.sign(xml, privateKey, references);

      expect(result.signedDocument).to.include("ds:Signature");
      expect(result.signedDocument).to.include('Id="sig1"');
    });

    it("should sign with empty URI reference (enveloped signature)", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });

      const references: SigningReference[] = [
        {
          uri: "",
          transforms: [
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/2001/10/xml-exc-c14n#",
          ],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        },
      ];

      const xml = "<root><test>content</test></root>";
      const result = signer.sign(xml, privateKey, references);

      const doc = new xmldom.DOMParser().parseFromString(result.signedDocument);
      const uriAttr = xpath.select1("//*[local-name(.)='Reference']/@URI", doc);
      isDomNode.assertIsAttributeNode(uriAttr);
      expect(uriAttr.value).to.equal("");
    });

    it("should sign with specific URI reference", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });

      const references: SigningReference[] = [
        {
          uri: "#test",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        },
      ];

      const xml = '<root><test id="test">content</test></root>';
      const result = signer.sign(xml, privateKey, references);

      const doc = new xmldom.DOMParser().parseFromString(result.signedDocument);
      const uriAttr = xpath.select1("//*[local-name(.)='Reference']/@URI", doc);
      isDomNode.assertIsAttributeNode(uriAttr);
      expect(uriAttr.value).to.equal("#test");
    });

    it("should include custom KeyInfo content with proper prefix handling", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        keyInfo: {
          getContent: (args) => {
            const prefix = args?.prefix;
            const ns = prefix ? `${prefix}:` : "";
            return `<${ns}X509Data><${ns}X509Certificate>test-cert</${ns}X509Certificate></${ns}X509Data>`;
          },
        },
      });

      const references: SigningReference[] = [
        {
          xpath: "//*[@id='test']",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        },
      ];

      const xml = '<root><test id="test">content</test></root>';
      const result = signer.sign(xml, privateKey, references);

      expect(result.signedDocument).to.include(
        "<X509Data><X509Certificate>test-cert</X509Certificate></X509Data>",
      );
    });

    it("should include custom KeyInfo content with prefix when signature uses prefix", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        prefix: "ds",
        keyInfo: {
          getContent: (args) => {
            const prefix = args?.prefix;
            const ns = prefix ? `${prefix}:` : "";
            return `<${ns}X509Data><${ns}X509Certificate>test-cert</${ns}X509Certificate></${ns}X509Data>`;
          },
        },
      });

      const references: SigningReference[] = [
        {
          xpath: "//*[@id='test']",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        },
      ];

      const xml = '<root><test id="test">content</test></root>';
      const result = signer.sign(xml, privateKey, references);

      expect(result.signedDocument).to.include(
        "<ds:X509Data><ds:X509Certificate>test-cert</ds:X509Certificate></ds:X509Data>",
      );
    });

    it("should include KeyInfo attributes", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        keyInfo: {
          getContent: () => "<custom>keyinfo</custom>",
          attributes: { Id: "keyinfo1", CustomAttr: "value", AnotherAttr: "test" },
        },
      });

      const references: SigningReference[] = [
        {
          xpath: "//*[@id='test']",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        },
      ];

      const xml = '<root><test id="test">content</test></root>';
      const result = signer.sign(xml, privateKey, references);

      const doc = new xmldom.DOMParser().parseFromString(result.signedDocument);
      const keyInfoEl = xpath.select1("//*[local-name(.)='KeyInfo']", doc);
      isDomNode.assertIsElementNode(keyInfoEl);
      expect(keyInfoEl.getAttribute("Id")).to.equal("keyinfo1");
      expect(keyInfoEl.getAttribute("CustomAttr")).to.equal("value");
      expect(keyInfoEl.getAttribute("AnotherAttr")).to.equal("test");
    });

    it("should include Reference attributes", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });

      const references: SigningReference[] = [
        {
          xpath: "//*[@id='test']",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
          attributes: { Id: "ref1", Type: "http://www.w3.org/2000/09/xmldsig#Object" },
        },
      ];

      const xml = '<root><test id="test">content</test></root>';
      const result = signer.sign(xml, privateKey, references);

      const doc = new xmldom.DOMParser().parseFromString(result.signedDocument);
      const referenceEl = xpath.select1("//*[local-name(.)='Reference']", doc);
      isDomNode.assertIsElementNode(referenceEl);
      expect(referenceEl.getAttribute("Id")).to.equal("ref1");
      expect(referenceEl.getAttribute("Type")).to.equal("http://www.w3.org/2000/09/xmldsig#Object");
    });

    it("should include Object elements", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        objects: [
          {
            content: "<Data>Test data</Data>",
            attributes: { Id: "obj1", MimeType: "text/xml" },
          },
        ],
      });

      const references: SigningReference[] = [
        {
          xpath: "//*[@id='test']",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        },
      ];

      const xml = '<root><test id="test">content</test></root>';
      const result = signer.sign(xml, privateKey, references);

      const doc = new xmldom.DOMParser().parseFromString(result.signedDocument);
      const objectEl = xpath.select1("//*[local-name(.)='Object'][@Id='obj1']", doc);
      isDomNode.assertIsElementNode(objectEl);
      expect(objectEl.getAttribute("MimeType")).to.equal("text/xml");
      expect(objectEl.textContent).to.include("Test data");
    });

    it("should handle inclusive namespace prefix lists", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        inclusiveNamespacesPrefixList: ["ns1", "ns2"],
      });

      const references: SigningReference[] = [
        {
          xpath: "//*[@id='test']",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
          inclusiveNamespacesPrefixList: ["ns3", "ns4"],
        },
      ];

      const xml =
        '<root xmlns:ns1="uri1" xmlns:ns2="uri2"><test id="test" xmlns:ns3="uri3" xmlns:ns4="uri4">content</test></root>';
      const result = signer.sign(xml, privateKey, references);

      const doc = new xmldom.DOMParser().parseFromString(result.signedDocument);

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
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });

      const references: SigningReference[] = [
        {
          xpath: "//*[@id='nonexistent']",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        },
      ];

      const xml = '<root><test id="test">content</test></root>';

      expect(() => signer.sign(xml, privateKey, references)).to.throw(
        /the following xpath cannot be signed because it was not found/,
      );
    });

    it("should throw error for external URI references", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });

      const references: SigningReference[] = [
        {
          uri: "http://example.com/document.xml",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        },
      ];

      const xml = '<root><test id="test">content</test></root>';

      expect(() => signer.sign(xml, privateKey, references)).to.throw(
        "External URI references are not supported for signing: http://example.com/document.xml",
      );
    });

    it("should throw error when URI is specified in attributes", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });

      const references: SigningReference[] = [
        {
          uri: "#test",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
          attributes: { URI: "#different-test" } as ReferenceAttributes, // This should be rejected
        },
      ];

      const xml = '<root><test id="test">content</test></root>';

      expect(() => signer.sign(xml, privateKey, references)).to.throw(
        "URI must be specified on the reference configuration, not in attributes",
      );
    });

    it("should work with custom ID attributes", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        idAttributes: ["customId", "id", "Id"],
      });

      const references: SigningReference[] = [
        {
          uri: "#data3",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        },
      ];

      const xml = '<root><test customId="data3">content</test></root>';
      const result = signer.sign(xml, privateKey, references);

      expect(result.signedDocument).to.include("Signature");
    });

    it("should work with namespace map", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        idAttributes: [
          {
            prefix: "wsu",
            localName: "Id",
            namespaceUri:
              "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
          },
        ],
      });

      const references: SigningReference[] = [
        {
          xpath:
            "//*[@*[local-name()='Id' and namespace-uri()='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd']='secure-data']",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        },
      ];

      const xml =
        '<root xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><test wsu:Id="secure-data">content</test></root>';
      const result = signer.sign(xml, privateKey, references);

      expect(result.signedDocument).to.include("Signature");
    });
  });

  describe("reusability", function () {
    it("should be reusable for multiple signing operations", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      });

      const references1: SigningReference[] = [
        {
          xpath: "//*[@id='test1']",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        },
      ];

      const references2: SigningReference[] = [
        {
          xpath: "//*[@id='test2']",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        },
      ];

      const xml1 = '<root><test id="test1">content1</test></root>';
      const xml2 = '<root><test id="test2">content2</test></root>';

      // First signing should work
      const result1 = signer.sign(xml1, privateKey, references1);
      expect(result1.signedDocument).to.include("Signature");

      // Second signing should also work (reusable)
      const result2 = signer.sign(xml2, privateKey, references2);
      expect(result2.signedDocument).to.include("Signature");
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
        const signer = new XmlDSigSigner({
          signatureAlgorithm: algorithm,
          canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        });

        const references: SigningReference[] = [
          {
            xpath: "//*[@id='test']",
            transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
            digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
          },
        ];

        const xml = '<root><test id="test">content</test></root>';
        const result = signer.sign(xml, privateKey, references);

        const doc = new xmldom.DOMParser().parseFromString(result.signedDocument);
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
        const signer = new XmlDSigSigner({
          signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
          canonicalizationAlgorithm: algorithm,
        });

        const references: SigningReference[] = [
          {
            xpath: "//*[@id='test']",
            transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
            digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
          },
        ];

        const xml = '<root><test id="test">content</test></root>';
        const result = signer.sign(xml, privateKey, references);

        const doc = new xmldom.DOMParser().parseFromString(result.signedDocument);
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
        const signer = new XmlDSigSigner({
          signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
          canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        });

        const references: SigningReference[] = [
          {
            xpath: "//*[@id='test']",
            transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
            digestAlgorithm: algorithm,
          },
        ];

        const xml = '<root><test id="test">content</test></root>';
        const result = signer.sign(xml, privateKey, references);

        const doc = new xmldom.DOMParser().parseFromString(result.signedDocument);
        const digestMethod = xpath.select1("//*[local-name(.)='DigestMethod']", doc);
        isDomNode.assertIsElementNode(digestMethod);
        expect(digestMethod.getAttribute("Algorithm")).to.equal(algorithm);
      });
    });
  });

  describe("integration with existing SignedXml functionality", function () {
    it("should produce signatures compatible with SignedXml verification", function () {
      const signer = new XmlDSigSigner({
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        keyInfo: {
          getContent: (args) => {
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

      const references: SigningReference[] = [
        {
          xpath: "//*[@id='test']",
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        },
      ];

      const xml = '<root><test id="test">content</test></root>';
      const result = signer.sign(xml, privateKey, references);

      // Verify the signature can be loaded and validated by SignedXml
      const doc = new xmldom.DOMParser().parseFromString(result.signedDocument);
      const signatureNode = xpath.select1(
        "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
        doc,
      );
      isDomNode.assertIsNodeLike(signatureNode);

      const verifier = new SignedXml();
      verifier.publicCert = publicCert;
      verifier.loadSignature(signatureNode);
      const isValid = verifier.checkSignature(result.signedDocument);

      expect(isValid).to.be.true;
    });
  });
});
