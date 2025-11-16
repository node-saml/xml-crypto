import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import { SignedXml, createOptionalCallbackFunction, XMLDSIG_URIS } from "../src";
import * as fs from "fs";
import * as crypto from "crypto";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";

const { SIGNATURE_ALGORITHMS, HASH_ALGORITHMS, CANONICALIZATION_ALGORITHMS, NAMESPACES } =
  XMLDSIG_URIS;

const signatureAlgorithms = [
  SIGNATURE_ALGORITHMS.RSA_SHA1,
  SIGNATURE_ALGORITHMS.RSA_SHA256,
  SIGNATURE_ALGORITHMS.RSA_SHA256_MGF1,
  SIGNATURE_ALGORITHMS.RSA_SHA512,
];

describe("Signature unit tests", function () {
  describe("sign and verify", function () {
    signatureAlgorithms.forEach((signatureAlgorithm) => {
      function signWith(signatureAlgorithm: string): string {
        const xml = '<root><x attr="value"></x></root>';
        const sig = new SignedXml();
        sig.privateKey = fs.readFileSync("./test/static/client.pem");

        sig.addReference({
          xpath: "//*[local-name(.)='x']",
          digestAlgorithm: HASH_ALGORITHMS.SHA1,
          transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
        });

        sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
        sig.signatureAlgorithm = signatureAlgorithm;
        sig.computeSignature(xml);
        return sig.getSignedXml();
      }

      function loadSignature(xml: string): SignedXml {
        const doc = new xmldom.DOMParser().parseFromString(xml);
        const node = xpath.select1(
          `//*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_URIS.NAMESPACES.ds}']`,
          doc,
        );
        isDomNode.assertIsNodeLike(node);
        const sig = new SignedXml();
        sig.publicCert = fs.readFileSync("./test/static/client_public.pem");
        sig.loadSignature(node);
        return sig;
      }

      it(`should verify signed xml with ${signatureAlgorithm}`, function () {
        const xml = signWith(signatureAlgorithm);
        const sig = loadSignature(xml);
        const res = sig.checkSignature(xml);
        expect(
          res,
          `expected all signatures with ${signatureAlgorithm} to be valid, but some reported invalid`,
        ).to.be.true;
      });

      it(`should fail verification of signed xml with ${signatureAlgorithm} after manipulation`, function () {
        const xml = signWith(signatureAlgorithm);
        const doc = new xmldom.DOMParser().parseFromString(xml);
        const node = xpath.select1("//*[local-name(.)='x']", doc);
        isDomNode.assertIsElementNode(node);
        const targetElement = node as Element;
        targetElement.setAttribute("attr", "manipulatedValue");
        const manipulatedXml = new xmldom.XMLSerializer().serializeToString(doc);

        const sig = loadSignature(manipulatedXml);
        const res = sig.checkSignature(manipulatedXml);
        expect(
          res,
          `expected all signatures with ${signatureAlgorithm} to be invalid, but some reported valid`,
        ).to.be.false;
      });
    });
  });

  describe("verify adds ID", function () {
    function nodeExists(doc, xpathArg) {
      if (!doc && !xpathArg) {
        return;
      }
      const node = xpath.select(xpathArg, doc);
      isDomNode.assertIsArrayOfNodes(node);
      expect(node.length, `xpath ${xpathArg} not found`).to.equal(1);
    }

    function verifyAddsId(mode, nsMode) {
      const xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';
      const sig = new SignedXml({ idMode: mode });
      sig.privateKey = fs.readFileSync("./test/static/client.pem");

      sig.addReference({
        xpath: "//*[local-name(.)='x']",
        digestAlgorithm: HASH_ALGORITHMS.SHA1,
        transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
      });
      sig.addReference({
        xpath: "//*[local-name(.)='y']",
        digestAlgorithm: HASH_ALGORITHMS.SHA1,
        transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
      });
      sig.addReference({
        xpath: "//*[local-name(.)='w']",
        digestAlgorithm: HASH_ALGORITHMS.SHA1,
        transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
      });

      sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
      sig.signatureAlgorithm = SIGNATURE_ALGORITHMS.RSA_SHA1;
      sig.computeSignature(xml);
      const signedXml = sig.getOriginalXmlWithIds();
      const doc = new xmldom.DOMParser().parseFromString(signedXml);

      const op = nsMode === "equal" ? "=" : "!=";

      const xpathArg = `//*[local-name(.)='{elem}' and '_{id}' = @*[local-name(.)='Id' and namespace-uri(.)${op}'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd']]`;

      //verify each of the signed nodes now has an "Id" attribute with the right value
      nodeExists(doc, xpathArg.replace("{id}", "0").replace("{elem}", "x"));
      nodeExists(doc, xpathArg.replace("{id}", "1").replace("{elem}", "y"));
      nodeExists(doc, xpathArg.replace("{id}", "2").replace("{elem}", "w"));
    }

    it("signer adds increasing different id attributes to elements", function () {
      verifyAddsId(null, "different");
    });

    it("signer adds increasing equal id attributes to elements", function () {
      verifyAddsId("wssecurity", "equal");
    });
  });

  it("signer adds references with namespaces", function () {
    const xml =
      '<root xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><name wsu:Id="_1">xml-crypto</name><repository wsu:Id="_2">github</repository></root>';
    const sig = new SignedXml({ idMode: "wssecurity" });

    sig.privateKey = fs.readFileSync("./test/static/client.pem");

    sig.addReference({
      xpath: "//*[@wsu:Id]",
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
      transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
    sig.signatureAlgorithm = SIGNATURE_ALGORITHMS.RSA_SHA1;
    sig.computeSignature(xml, {
      existingPrefixes: {
        wsu: NAMESPACES.wsu,
      },
    });

    const signedXml = sig.getSignatureXml();
    const doc = new xmldom.DOMParser().parseFromString(signedXml);
    const references = xpath.select("//*[local-name(.)='Reference']", doc);
    isDomNode.assertIsArrayOfNodes(references);
    expect(references.length).to.equal(2);
  });

  describe("signer does not duplicate id attributes", function () {
    function verifyDoesNotDuplicateIdAttributes(prefix: string, idMode?: "wssecurity") {
      const xml = `<x xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' ${prefix}Id='_1'></x>`;
      const sig = new SignedXml({ idMode });
      sig.privateKey = fs.readFileSync("./test/static/client.pem");
      sig.addReference({
        xpath: "//*[local-name(.)='x']",
        digestAlgorithm: HASH_ALGORITHMS.SHA1,
        transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
      });
      sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
      sig.signatureAlgorithm = SIGNATURE_ALGORITHMS.RSA_SHA1;
      sig.computeSignature(xml);
      const signedXml = sig.getOriginalXmlWithIds();
      const doc = new xmldom.DOMParser().parseFromString(signedXml);
      const attrs = xpath.select("//@*", doc);
      isDomNode.assertIsArrayOfNodes(attrs);
      expect(attrs.length, "wrong number of attributes").to.equal(2);
    }

    it("signer does not implicitly duplicate existing id attributes", function () {
      verifyDoesNotDuplicateIdAttributes("");
    });

    it("signer does not explicitly duplicate existing id attributes", function () {
      verifyDoesNotDuplicateIdAttributes("wsu:", "wssecurity");
    });
  });

  it("signer adds custom attributes to the signature root node", function () {
    const xml = '<root xmlns="ns"><name>xml-crypto</name><repository>github</repository></root>';
    const sig = new SignedXml();
    const attrs = {
      Id: "signatureTest",
      data: "dataValue",
      xmlns: "http://custom-xmlns#",
    };

    sig.privateKey = fs.readFileSync("./test/static/client.pem");

    sig.addReference({
      xpath: "//*[local-name(.)='name']",
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
      transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
    sig.signatureAlgorithm = SIGNATURE_ALGORITHMS.RSA_SHA1;
    sig.computeSignature(xml, {
      attrs: attrs,
    });

    const signedXml = sig.getSignatureXml();
    const doc = new xmldom.DOMParser().parseFromString(signedXml);
    const signatureNode = doc.documentElement;

    expect(attrs.Id, `Id attribute is not equal to the expected value: "${attrs.Id}"`).to.equal(
      signatureNode.getAttribute("Id"),
    );
    expect(
      attrs.data,
      `data attribute is not equal to the expected value: "${attrs.data}"`,
    ).to.equal(signatureNode.getAttribute("data"));
    expect(attrs.xmlns, "xmlns attribute can not be overridden").not.to.equal(
      signatureNode.getAttribute("xmlns"),
    );
    expect(
      signatureNode.getAttribute("xmlns"),
      'xmlns attribute is not equal to the expected value: "http://www.w3.org/2000/09/xmldsig#"',
    ).to.equal(XMLDSIG_URIS.NAMESPACES.ds);
  });

  it("signer appends signature to the root node by default", function () {
    const xml = "<root><name>xml-crypto</name><repository>github</repository></root>";
    const sig = new SignedXml();

    sig.privateKey = fs.readFileSync("./test/static/client.pem");
    sig.addReference({
      xpath: "//*[local-name(.)='name']",
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
      transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });
    sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
    sig.signatureAlgorithm = SIGNATURE_ALGORITHMS.RSA_SHA1;
    sig.computeSignature(xml);

    const doc = new xmldom.DOMParser().parseFromString(sig.getSignedXml());

    const lastChild = doc.documentElement.lastChild;
    isDomNode.assertIsElementNode(lastChild);
    expect(
      lastChild.localName,
      "the signature must be appended to the root node by default",
    ).to.equal("Signature");
  });

  it("signer appends signature to a reference node", function () {
    const xml = "<root><name>xml-crypto</name><repository>github</repository></root>";
    const sig = new SignedXml();

    sig.privateKey = fs.readFileSync("./test/static/client.pem");
    sig.addReference({
      xpath: "//*[local-name(.)='repository']",
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
      transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
    sig.signatureAlgorithm = SIGNATURE_ALGORITHMS.RSA_SHA1;
    sig.computeSignature(xml, {
      location: {
        reference: "/root/name",
        action: "append",
      },
    });

    const doc = new xmldom.DOMParser().parseFromString(sig.getSignedXml());
    const referenceNode = xpath.select1("/root/name", doc);

    isDomNode.assertIsNodeLike(referenceNode);
    const lastChild = referenceNode.lastChild;

    isDomNode.assertIsElementNode(lastChild);
    expect(lastChild.localName, "the signature should be appended to root/name").to.equal(
      "Signature",
    );
  });

  it("signer prepends signature to a reference node", function () {
    const xml = "<root><name>xml-crypto</name><repository>github</repository></root>";
    const sig = new SignedXml();

    sig.privateKey = fs.readFileSync("./test/static/client.pem");
    sig.addReference({
      xpath: "//*[local-name(.)='repository']",
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
      transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
    sig.signatureAlgorithm = SIGNATURE_ALGORITHMS.RSA_SHA1;
    sig.computeSignature(xml, {
      location: {
        reference: "/root/name",
        action: "prepend",
      },
    });

    const doc = new xmldom.DOMParser().parseFromString(sig.getSignedXml());
    const referenceNode = xpath.select1("/root/name", doc);
    isDomNode.assertIsNodeLike(referenceNode);
    const firstChild = referenceNode.firstChild;

    isDomNode.assertIsElementNode(firstChild);
    expect(firstChild.localName, "the signature should be prepended to root/name").to.equal(
      "Signature",
    );
  });

  it("signer inserts signature before a reference node", function () {
    const xml = "<root><name>xml-crypto</name><repository>github</repository></root>";
    const sig = new SignedXml();

    sig.privateKey = fs.readFileSync("./test/static/client.pem");
    sig.addReference({
      xpath: "//*[local-name(.)='repository']",
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
      transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
    sig.signatureAlgorithm = SIGNATURE_ALGORITHMS.RSA_SHA1;
    sig.computeSignature(xml, {
      location: {
        reference: "/root/name",
        action: "before",
      },
    });

    const doc = new xmldom.DOMParser().parseFromString(sig.getSignedXml());
    const referenceNode = xpath.select1("/root/name", doc);
    isDomNode.assertIsNodeLike(referenceNode);
    const previousSibling = referenceNode.previousSibling;

    isDomNode.assertIsElementNode(previousSibling);
    expect(
      previousSibling.localName,
      "the signature should be inserted before to root/name",
    ).to.equal("Signature");
  });

  it("signer inserts signature after a reference node", function () {
    const xml = "<root><name>xml-crypto</name><repository>github</repository></root>";
    const sig = new SignedXml();

    sig.privateKey = fs.readFileSync("./test/static/client.pem");
    sig.addReference({
      xpath: "//*[local-name(.)='repository']",
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
      transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
    sig.signatureAlgorithm = SIGNATURE_ALGORITHMS.RSA_SHA1;
    sig.computeSignature(xml, {
      location: {
        reference: "/root/name",
        action: "after",
      },
    });

    const doc = new xmldom.DOMParser().parseFromString(sig.getSignedXml());
    const referenceNode = xpath.select1("/root/name", doc);

    isDomNode.assertIsNodeLike(referenceNode);
    const nextSibling = referenceNode.nextSibling;

    isDomNode.assertIsElementNode(nextSibling);
    expect(nextSibling.localName, "the signature should be inserted after to root/name").to.equal(
      "Signature",
    );
  });

  it("signer creates signature with correct structure", function () {
    class DummyDigest {
      getHash = function () {
        return "dummy digest";
      };

      getAlgorithmName = function () {
        return "dummy digest algorithm";
      };
    }

    class DummySignatureAlgorithm {
      verifySignature = function () {
        return true;
      };

      getSignature = function () {
        return "dummy signature";
      };

      getAlgorithmName = function () {
        return "dummy algorithm";
      };
    }

    class DummyTransformation {
      includeComments = false;
      process = function () {
        return "< x/>";
      };

      getAlgorithmName = function () {
        return "dummy transformation";
      };
    }

    class DummyCanonicalization {
      includeComments = false;
      process = function () {
        return "< x/>";
      };

      getAlgorithmName = function () {
        return "dummy canonicalization";
      };
    }

    const xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';
    const sig = new SignedXml();

    sig.CanonicalizationAlgorithms["http://DummyTransformation"] = DummyTransformation;
    sig.CanonicalizationAlgorithms["http://DummyCanonicalization"] = DummyCanonicalization;
    sig.HashAlgorithms["http://dummyDigest"] = DummyDigest;
    sig.SignatureAlgorithms["http://dummySignatureAlgorithm"] = DummySignatureAlgorithm;

    sig.signatureAlgorithm = "http://dummySignatureAlgorithm";
    sig.getKeyInfoContent = function () {
      return "dummy key info";
    };
    sig.canonicalizationAlgorithm = "http://DummyCanonicalization";
    sig.privateKey = "";

    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      transforms: ["http://DummyTransformation"],
      digestAlgorithm: "http://dummyDigest",
    });
    sig.addReference({
      xpath: "//*[local-name(.)='y']",
      transforms: ["http://DummyTransformation"],
      digestAlgorithm: "http://dummyDigest",
    });
    sig.addReference({
      xpath: "//*[local-name(.)='w']",
      transforms: ["http://DummyTransformation"],
      digestAlgorithm: "http://dummyDigest",
    });

    sig.computeSignature(xml);
    const signature = sig.getSignatureXml();
    const expected =
      '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' +
      "<SignedInfo>" +
      '<CanonicalizationMethod Algorithm="dummy canonicalization"/>' +
      '<SignatureMethod Algorithm="dummy algorithm"/>' +
      '<Reference URI="#_0">' +
      "<Transforms>" +
      '<Transform Algorithm="dummy transformation"/>' +
      "</Transforms>" +
      '<DigestMethod Algorithm="dummy digest algorithm"/>' +
      "<DigestValue>dummy digest</DigestValue>" +
      "</Reference>" +
      '<Reference URI="#_1">' +
      "<Transforms>" +
      '<Transform Algorithm="dummy transformation"/>' +
      "</Transforms>" +
      '<DigestMethod Algorithm="dummy digest algorithm"/>' +
      "<DigestValue>dummy digest</DigestValue>" +
      "</Reference>" +
      '<Reference URI="#_2">' +
      "<Transforms>" +
      '<Transform Algorithm="dummy transformation"/>' +
      "</Transforms>" +
      '<DigestMethod Algorithm="dummy digest algorithm"/>' +
      "<DigestValue>dummy digest</DigestValue>" +
      "</Reference>" +
      "</SignedInfo>" +
      "<SignatureValue>dummy signature</SignatureValue>" +
      "<KeyInfo>" +
      "dummy key info" +
      "</KeyInfo>" +
      "</Signature>";

    expect(expected, "wrong signature format").to.equal(signature);

    const signedXml = sig.getSignedXml();
    const expectedSignedXml =
      '<root><x xmlns="ns" Id="_0"/><y attr="value" Id="_1"/><z><w Id="_2"/></z>' +
      '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' +
      "<SignedInfo>" +
      '<CanonicalizationMethod Algorithm="dummy canonicalization"/>' +
      '<SignatureMethod Algorithm="dummy algorithm"/>' +
      '<Reference URI="#_0">' +
      "<Transforms>" +
      '<Transform Algorithm="dummy transformation"/>' +
      "</Transforms>" +
      '<DigestMethod Algorithm="dummy digest algorithm"/>' +
      "<DigestValue>dummy digest</DigestValue>" +
      "</Reference>" +
      '<Reference URI="#_1">' +
      "<Transforms>" +
      '<Transform Algorithm="dummy transformation"/>' +
      "</Transforms>" +
      '<DigestMethod Algorithm="dummy digest algorithm"/>' +
      "<DigestValue>dummy digest</DigestValue>" +
      "</Reference>" +
      '<Reference URI="#_2">' +
      "<Transforms>" +
      '<Transform Algorithm="dummy transformation"/>' +
      "</Transforms>" +
      '<DigestMethod Algorithm="dummy digest algorithm"/>' +
      "<DigestValue>dummy digest</DigestValue>" +
      "</Reference>" +
      "</SignedInfo>" +
      "<SignatureValue>dummy signature</SignatureValue>" +
      "<KeyInfo>" +
      "dummy key info" +
      "</KeyInfo>" +
      "</Signature>" +
      "</root>";

    expect(expectedSignedXml, "wrong signedXml format").to.equal(signedXml);

    const originalXmlWithIds = sig.getOriginalXmlWithIds();
    const expectedOriginalXmlWithIds =
      '<root><x xmlns="ns" Id="_0"/><y attr="value" Id="_1"/><z><w Id="_2"/></z></root>';
    expect(expectedOriginalXmlWithIds, "wrong OriginalXmlWithIds").to.equal(originalXmlWithIds);
  });

  it("signer creates signature with correct structure (with prefix)", function () {
    const prefix = "ds";

    class DummyDigest {
      getHash = function () {
        return "dummy digest";
      };

      getAlgorithmName = function () {
        return "dummy digest algorithm";
      };
    }

    class DummySignatureAlgorithm {
      verifySignature = function () {
        return true;
      };

      getSignature = function () {
        return "dummy signature";
      };

      getAlgorithmName = function () {
        return "dummy algorithm";
      };
    }

    class DummyTransformation {
      includeComments = false;
      process = function () {
        return "< x/>";
      };

      getAlgorithmName = function () {
        return "dummy transformation";
      };
    }

    class DummyCanonicalization {
      includeComments = false;
      process = function () {
        return "< x/>";
      };

      getAlgorithmName = function () {
        return "dummy canonicalization";
      };
    }

    const xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';
    const sig = new SignedXml();

    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");
    sig.CanonicalizationAlgorithms["http://DummyTransformation"] = DummyTransformation;
    sig.CanonicalizationAlgorithms["http://DummyCanonicalization"] = DummyCanonicalization;
    sig.HashAlgorithms["http://dummyDigest"] = DummyDigest;
    sig.SignatureAlgorithms["http://dummySignatureAlgorithm"] = DummySignatureAlgorithm;

    sig.signatureAlgorithm = "http://dummySignatureAlgorithm";
    sig.canonicalizationAlgorithm = "http://DummyCanonicalization";
    sig.privateKey = "";

    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      transforms: ["http://DummyTransformation"],
      digestAlgorithm: "http://dummyDigest",
    });
    sig.addReference({
      xpath: "//*[local-name(.)='y']",
      transforms: ["http://DummyTransformation"],
      digestAlgorithm: "http://dummyDigest",
    });
    sig.addReference({
      xpath: "//*[local-name(.)='w']",
      transforms: ["http://DummyTransformation"],
      digestAlgorithm: "http://dummyDigest",
    });

    sig.computeSignature(xml, { prefix: prefix });
    const signature = sig.getSignatureXml();

    const expected =
      '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
      "<ds:SignedInfo>" +
      '<ds:CanonicalizationMethod Algorithm="dummy canonicalization"/>' +
      '<ds:SignatureMethod Algorithm="dummy algorithm"/>' +
      '<ds:Reference URI="#_0">' +
      "<ds:Transforms>" +
      '<ds:Transform Algorithm="dummy transformation"/>' +
      "</ds:Transforms>" +
      '<ds:DigestMethod Algorithm="dummy digest algorithm"/>' +
      "<ds:DigestValue>dummy digest</ds:DigestValue>" +
      "</ds:Reference>" +
      '<ds:Reference URI="#_1">' +
      "<ds:Transforms>" +
      '<ds:Transform Algorithm="dummy transformation"/>' +
      "</ds:Transforms>" +
      '<ds:DigestMethod Algorithm="dummy digest algorithm"/>' +
      "<ds:DigestValue>dummy digest</ds:DigestValue>" +
      "</ds:Reference>" +
      '<ds:Reference URI="#_2">' +
      "<ds:Transforms>" +
      '<ds:Transform Algorithm="dummy transformation"/>' +
      "</ds:Transforms>" +
      '<ds:DigestMethod Algorithm="dummy digest algorithm"/>' +
      "<ds:DigestValue>dummy digest</ds:DigestValue>" +
      "</ds:Reference>" +
      "</ds:SignedInfo>" +
      "<ds:SignatureValue>dummy signature</ds:SignatureValue>" +
      "<ds:KeyInfo>" +
      "<ds:X509Data>" +
      "<ds:X509Certificate>MIIBxDCCAW6gAwIBAgIQxUSXFzWJYYtOZnmmuOMKkjANBgkqhkiG9w0BAQQFADAWMRQwEgYDVQQDEwtSb290IEFnZW5jeTAeFw0wMzA3MDgxODQ3NTlaFw0zOTEyMzEyMzU5NTlaMB8xHTAbBgNVBAMTFFdTRTJRdWlja1N0YXJ0Q2xpZW50MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+L6aB9x928noY4+0QBsXnxkQE4quJl7c3PUPdVu7k9A02hRG481XIfWhrDY5i7OEB7KGW7qFJotLLeMec/UkKUwCgv3VvJrs2nE9xO3SSWIdNzADukYh+Cxt+FUU6tUkDeqg7dqwivOXhuOTRyOI3HqbWTbumaLdc8jufz2LhaQIDAQABo0swSTBHBgNVHQEEQDA+gBAS5AktBh0dTwCNYSHcFmRjoRgwFjEUMBIGA1UEAxMLUm9vdCBBZ2VuY3mCEAY3bACqAGSKEc+41KpcNfQwDQYJKoZIhvcNAQEEBQADQQAfIbnMPVYkNNfX1tG1F+qfLhHwJdfDUZuPyRPucWF5qkh6sSdWVBY5sT/txBnVJGziyO8DPYdu2fPMER8ajJfl</ds:X509Certificate>" +
      "</ds:X509Data>" +
      "</ds:KeyInfo>" +
      "</ds:Signature>";

    expect(signature, "wrong signature format").to.equal(expected);

    const signedXml = sig.getSignedXml();
    const expectedSignedXml =
      '<root><x xmlns="ns" Id="_0"/><y attr="value" Id="_1"/><z><w Id="_2"/></z>' +
      '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
      "<ds:SignedInfo>" +
      '<ds:CanonicalizationMethod Algorithm="dummy canonicalization"/>' +
      '<ds:SignatureMethod Algorithm="dummy algorithm"/>' +
      '<ds:Reference URI="#_0">' +
      "<ds:Transforms>" +
      '<ds:Transform Algorithm="dummy transformation"/>' +
      "</ds:Transforms>" +
      '<ds:DigestMethod Algorithm="dummy digest algorithm"/>' +
      "<ds:DigestValue>dummy digest</ds:DigestValue>" +
      "</ds:Reference>" +
      '<ds:Reference URI="#_1">' +
      "<ds:Transforms>" +
      '<ds:Transform Algorithm="dummy transformation"/>' +
      "</ds:Transforms>" +
      '<ds:DigestMethod Algorithm="dummy digest algorithm"/>' +
      "<ds:DigestValue>dummy digest</ds:DigestValue>" +
      "</ds:Reference>" +
      '<ds:Reference URI="#_2">' +
      "<ds:Transforms>" +
      '<ds:Transform Algorithm="dummy transformation"/>' +
      "</ds:Transforms>" +
      '<ds:DigestMethod Algorithm="dummy digest algorithm"/>' +
      "<ds:DigestValue>dummy digest</ds:DigestValue>" +
      "</ds:Reference>" +
      "</ds:SignedInfo>" +
      "<ds:SignatureValue>dummy signature</ds:SignatureValue>" +
      "<ds:KeyInfo>" +
      "<ds:X509Data>" +
      "<ds:X509Certificate>MIIBxDCCAW6gAwIBAgIQxUSXFzWJYYtOZnmmuOMKkjANBgkqhkiG9w0BAQQFADAWMRQwEgYDVQQDEwtSb290IEFnZW5jeTAeFw0wMzA3MDgxODQ3NTlaFw0zOTEyMzEyMzU5NTlaMB8xHTAbBgNVBAMTFFdTRTJRdWlja1N0YXJ0Q2xpZW50MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+L6aB9x928noY4+0QBsXnxkQE4quJl7c3PUPdVu7k9A02hRG481XIfWhrDY5i7OEB7KGW7qFJotLLeMec/UkKUwCgv3VvJrs2nE9xO3SSWIdNzADukYh+Cxt+FUU6tUkDeqg7dqwivOXhuOTRyOI3HqbWTbumaLdc8jufz2LhaQIDAQABo0swSTBHBgNVHQEEQDA+gBAS5AktBh0dTwCNYSHcFmRjoRgwFjEUMBIGA1UEAxMLUm9vdCBBZ2VuY3mCEAY3bACqAGSKEc+41KpcNfQwDQYJKoZIhvcNAQEEBQADQQAfIbnMPVYkNNfX1tG1F+qfLhHwJdfDUZuPyRPucWF5qkh6sSdWVBY5sT/txBnVJGziyO8DPYdu2fPMER8ajJfl</ds:X509Certificate>" +
      "</ds:X509Data>" +
      "</ds:KeyInfo>" +
      "</ds:Signature>" +
      "</root>";

    expect(signedXml, "wrong signedXml format").to.equal(expectedSignedXml);

    const originalXmlWithIds = sig.getOriginalXmlWithIds();
    const expectedOriginalXmlWithIds =
      '<root><x xmlns="ns" Id="_0"/><y attr="value" Id="_1"/><z><w Id="_2"/></z></root>';
    expect(originalXmlWithIds, "wrong OriginalXmlWithIds").to.equal(expectedOriginalXmlWithIds);
  });

  it("signer creates correct signature values", function () {
    const xml =
      '<root><x xmlns="ns" Id="_0"></x><y attr="value" Id="_1"></y><z><w Id="_2"></w></z></root>';
    const sig = new SignedXml();
    sig.privateKey = fs.readFileSync("./test/static/client.pem");

    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
      transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });
    sig.addReference({
      xpath: "//*[local-name(.)='y']",
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
      transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });
    sig.addReference({
      xpath: "//*[local-name(.)='w']",
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
      transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
    sig.signatureAlgorithm = SIGNATURE_ALGORITHMS.RSA_SHA1;
    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();
    const expected =
      '<root><x xmlns="ns" Id="_0"/><y attr="value" Id="_1"/><z><w Id="_2"/></z>' +
      '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' +
      "<SignedInfo>" +
      '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
      '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>' +
      '<Reference URI="#_0">' +
      "<Transforms>" +
      '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms>' +
      '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
      "<DigestValue>b5GCZ2xpP5T7tbLWBTkOl4CYupQ=</DigestValue>" +
      "</Reference>" +
      '<Reference URI="#_1">' +
      "<Transforms>" +
      '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
      "</Transforms>" +
      '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
      "<DigestValue>4Pq/sBri+AyOtxtSFsPSOyylyzk=</DigestValue>" +
      "</Reference>" +
      '<Reference URI="#_2">' +
      "<Transforms>" +
      '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
      "</Transforms>" +
      '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
      "<DigestValue>6I7SDu1iV2YOajTlf+iMLIBfLnE=</DigestValue>" +
      "</Reference>" +
      "</SignedInfo>" +
      "<SignatureValue>NejzGB9MDUddKCt3GL2vJhEd5q6NBuhLdQc3W4bJI5q34hk7Hk6zBRoW3OliX+/f7Hpi9y0INYoqMSUfrsAVm3IuPzUETKlI6xiNZo07ULRj1DwxRo6cU66ar1EKUQLRuCZas795FjB8jvUI2lyhcax/00uMJ+Cjf4bwAQ+9gOQ=</SignatureValue>" +
      "</Signature>" +
      "</root>";

    expect(expected, "wrong signature format").to.equal(signedXml);
  });

  it("signer creates correct signature values using async callback", function () {
    class DummySignatureAlgorithm {
      verifySignature = function () {
        return true;
      };

      getSignature = createOptionalCallbackFunction(
        (signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike) => {
          const signer = crypto.createSign("RSA-SHA1");
          signer.update(signedInfo);
          const res = signer.sign(privateKey, "base64");
          return res;
        },
      );

      getAlgorithmName = function () {
        return SIGNATURE_ALGORITHMS.RSA_SHA1;
      };
    }

    const xml =
      '<root><x xmlns="ns" Id="_0"></x><y attr="value" Id="_1"></y><z><w Id="_2"></w></z></root>';
    const sig = new SignedXml();
    sig.SignatureAlgorithms["http://dummySignatureAlgorithmAsync"] = DummySignatureAlgorithm;
    sig.signatureAlgorithm = "http://dummySignatureAlgorithmAsync";
    sig.privateKey = fs.readFileSync("./test/static/client.pem");

    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
      transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });
    sig.addReference({
      xpath: "//*[local-name(.)='y']",
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
      transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });
    sig.addReference({
      xpath: "//*[local-name(.)='w']",
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
      transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
    sig.computeSignature(xml, function () {
      const signedXml = sig.getSignedXml();
      const expected =
        '<root><x xmlns="ns" Id="_0"/><y attr="value" Id="_1"/><z><w Id="_2"/></z>' +
        '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' +
        "<SignedInfo>" +
        '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
        '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>' +
        '<Reference URI="#_0">' +
        "<Transforms>" +
        '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms>' +
        '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
        "<DigestValue>b5GCZ2xpP5T7tbLWBTkOl4CYupQ=</DigestValue>" +
        "</Reference>" +
        '<Reference URI="#_1">' +
        "<Transforms>" +
        '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
        "</Transforms>" +
        '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
        "<DigestValue>4Pq/sBri+AyOtxtSFsPSOyylyzk=</DigestValue>" +
        "</Reference>" +
        '<Reference URI="#_2">' +
        "<Transforms>" +
        '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
        "</Transforms>" +
        '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
        "<DigestValue>6I7SDu1iV2YOajTlf+iMLIBfLnE=</DigestValue>" +
        "</Reference>" +
        "</SignedInfo>" +
        "<SignatureValue>NejzGB9MDUddKCt3GL2vJhEd5q6NBuhLdQc3W4bJI5q34hk7Hk6zBRoW3OliX+/f7Hpi9y0INYoqMSUfrsAVm3IuPzUETKlI6xiNZo07ULRj1DwxRo6cU66ar1EKUQLRuCZas795FjB8jvUI2lyhcax/00uMJ+Cjf4bwAQ+9gOQ=</SignatureValue>" +
        "</Signature>" +
        "</root>";

      expect(expected, "wrong signature format").to.equal(signedXml);
    });
  });

  describe("verify existing signature", function () {
    describe("pass loading signatures", function () {
      function passLoadSignature(file: string, toString?: boolean) {
        const xml = fs.readFileSync(file, "utf8");
        const doc = new xmldom.DOMParser().parseFromString(xml);
        const signature = xpath.select1(
          `/*//*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_URIS.NAMESPACES.ds}']`,
          doc,
        );
        isDomNode.assertIsElementNode(signature);
        const sig = new SignedXml();
        sig.loadSignature(toString ? signature.toString() : signature);

        expect(sig.canonicalizationAlgorithm, "wrong canonicalization method").to.equal(
          CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
        );

        expect(sig.signatureAlgorithm, "wrong signature method").to.equal(
          SIGNATURE_ALGORITHMS.RSA_SHA1,
        );

        sig.getCertFromKeyInfo = (keyInfo) => {
          isDomNode.assertIsNodeLike(keyInfo);
          const keyInfoContents = xpath.select1(
            "//*[local-name(.)='KeyInfo']/*[local-name(.)='dummyKey']",
            keyInfo,
          );
          isDomNode.assertIsNodeLike(keyInfoContents);
          const firstChild = keyInfoContents.firstChild;
          isDomNode.assertIsTextNode(firstChild);
          expect(firstChild.data, "keyInfo clause not correctly loaded").to.equal("1234");

          return fs.readFileSync("./test/static/client.pem", "latin1");
        };

        const checkedSignature = sig.checkSignature(xml);
        expect(checkedSignature).to.be.true;

        /* eslint-disable-next-line deprecation/deprecation */
        expect(sig.getReferences().length).to.equal(3);
        expect(sig.getSignedReferences().length).to.equal(3);

        const digests = [
          "b5GCZ2xpP5T7tbLWBTkOl4CYupQ=",
          "K4dI497ZCxzweDIrbndUSmtoezY=",
          "sH1gxKve8wlU8LlFVa2l6w3HMJ0=",
        ];

        const firstGrandchild = doc.firstChild?.firstChild;
        isDomNode.assertIsElementNode(firstGrandchild);
        const matchedReference = sig.validateElementAgainstReferences(firstGrandchild, doc);
        expect(matchedReference).to.not.be.false;

        /* eslint-disable-next-line deprecation/deprecation */
        for (let i = 0; i < sig.getReferences().length; i++) {
          /* eslint-disable-next-line deprecation/deprecation */
          const ref = sig.getReferences()[i];
          const expectedUri = `#_${i}`;
          expect(
            ref.uri,
            `wrong uri for index ${i}. expected: ${expectedUri} actual: ${ref.uri}`,
          ).to.equal(expectedUri);
          expect(ref.transforms.length).to.equal(1);
          expect(ref.transforms[0]).to.equal(CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N);
          expect(ref.digestValue).to.equal(digests[i]);
          expect(ref.digestAlgorithm).to.equal(HASH_ALGORITHMS.SHA1);
        }
      }

      it("correctly loads signature", function () {
        passLoadSignature("./test/static/valid_signature.xml");
      });

      it("correctly loads signature with validation", function () {
        passLoadSignature("./test/static/valid_signature.xml", true);
      });

      it("correctly loads signature with root level sig namespace", function () {
        passLoadSignature("./test/static/valid_signature_with_root_level_sig_namespace.xml");
      });
    });

    describe("pass verify signature", function () {
      function loadSignature(xml: string, idMode?: "wssecurity") {
        const doc = new xmldom.DOMParser().parseFromString(xml);
        const node = xpath.select1(
          `//*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_URIS.NAMESPACES.ds}']`,
          doc,
        );
        isDomNode.assertIsNodeLike(node);
        const sig = new SignedXml({ idMode });
        sig.publicCert = fs.readFileSync("./test/static/client_public.pem");
        sig.loadSignature(node);

        return sig;
      }

      function passValidSignature(file: string, mode?: "wssecurity") {
        const xml = fs.readFileSync(file, "utf8");
        const sig = loadSignature(xml, mode);
        const res = sig.checkSignature(xml);
        expect(res, "expected all signatures to be valid, but some reported invalid").to.be.true;
        /* eslint-disable-next-line deprecation/deprecation */
        expect(sig.getSignedReferences().length).to.equal(sig.getReferences().length);
      }

      function failInvalidSignature(file: string, idMode?: "wssecurity") {
        const xml = fs.readFileSync(file).toString();
        const sig = loadSignature(xml, idMode);
        const res = sig.checkSignature(xml);
        expect(res, "expected a signature to be invalid, but all were reported valid").to.be.false;
        expect(sig.getSignedReferences().length).to.equal(0);
      }

      function throwsValidatingSignature(file: string, idMode?: "wssecurity") {
        const xml = fs.readFileSync(file).toString();
        const sig = loadSignature(xml, idMode);
        expect(
          () => sig.checkSignature(xml),
          "expected an error to be thrown because signatures couldn't be checked for validity",
        ).to.throw();
        expect(sig.getSignedReferences().length).to.equal(0);
      }

      it("verifies valid signature", function () {
        passValidSignature("./test/static/valid_signature.xml");
      });

      it("verifies valid signature with lowercase id attribute", function () {
        passValidSignature("./test/static/valid_signature_with_lowercase_id_attribute.xml");
      });

      it("verifies valid signature with wsu", function () {
        passValidSignature("./test/static/valid_signature wsu.xml", "wssecurity");
      });

      it("verifies valid signature with reference keyInfo", function () {
        passValidSignature("./test/static/valid_signature_with_reference_keyInfo.xml");
      });

      it("verifies valid signature with whitespace in digestvalue", function () {
        passValidSignature("./test/static/valid_signature_with_whitespace_in_digestvalue.xml");
      });

      it("verifies valid utf8 signature", function () {
        passValidSignature("./test/static/valid_signature_utf8.xml");
      });

      it("verifies valid signature with unused prefixes", function () {
        passValidSignature("./test/static/valid_signature_with_unused_prefixes.xml");
      });

      it("verifies valid signature without transforms element", function () {
        passValidSignature("./test/static/valid_signature_without_transforms_element.xml");
      });

      it("throws validating signature - signature value", function () {
        throwsValidatingSignature("./test/static/invalid_signature - signature value.xml");
      });

      it("fails invalid signature - hash", function () {
        failInvalidSignature("./test/static/invalid_signature - hash.xml");
      });

      it("fails invalid signature - non existing reference", function () {
        failInvalidSignature("./test/static/invalid_signature - non existing reference.xml");
      });

      it("fails invalid signature - changed content", function () {
        failInvalidSignature("./test/static/invalid_signature - changed content.xml");
      });

      it("fails invalid signature - wsu - invalid signature value", function () {
        failInvalidSignature(
          "./test/static/invalid_signature - wsu - invalid signature value.xml",
          "wssecurity",
        );
      });

      it("fails invalid signature - wsu - hash", function () {
        failInvalidSignature("./test/static/invalid_signature - wsu - hash.xml", "wssecurity");
      });

      it("fails invalid signature - wsu - non existing reference", function () {
        failInvalidSignature(
          "./test/static/invalid_signature - wsu - non existing reference.xml",
          "wssecurity",
        );
      });

      it("fails invalid signature - wsu - changed content", function () {
        failInvalidSignature(
          "./test/static/invalid_signature - wsu - changed content.xml",
          "wssecurity",
        );
      });

      it("fails invalid signature without transforms element", function () {
        failInvalidSignature("./test/static/invalid_signature_without_transforms_element.xml");
      });
    });
  });

  it("allow empty reference uri when signing", function () {
    const xml = "<root><x /></root>";
    const sig = new SignedXml();
    sig.privateKey = fs.readFileSync("./test/static/client.pem");

    sig.addReference({
      xpath: "//*[local-name(.)='root']",
      transforms: [XMLDSIG_URIS.TRANSFORM_ALGORITHMS.ENVELOPED_SIGNATURE],
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
      uri: "",
      digestValue: "",
      inclusiveNamespacesPrefixList: [],
      isEmptyUri: true,
    });

    sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
    sig.signatureAlgorithm = SIGNATURE_ALGORITHMS.RSA_SHA1;
    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();
    const doc = new xmldom.DOMParser().parseFromString(signedXml);
    const URI = xpath.select1("//*[local-name(.)='Reference']/@URI", doc);
    isDomNode.assertIsAttributeNode(URI);
    expect(URI.value, `uri should be empty but instead was ${URI.value}`).to.equal("");
  });

  it("signer appends signature to a non-existing reference node", function () {
    const xml = "<root><name>xml-crypto</name><repository>github</repository></root>";
    const sig = new SignedXml();

    sig.privateKey = fs.readFileSync("./test/static/client.pem");
    sig.addReference({
      xpath: "//*[local-name(.)='repository']",
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
      transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    try {
      sig.computeSignature(xml, {
        location: {
          reference: "/root/foobar",
          action: "append",
        },
      });
      expect.fail("Expected an error to be thrown");
    } catch (err) {
      expect(err).not.to.be.an.instanceof(TypeError);
    }
  });

  it("signer adds existing prefixes", function () {
    function getKeyInfoContentWithAssertionId({ assertionId }) {
      return (
        `<wsse:SecurityTokenReference wsse11:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1" wsu:Id="0" ` +
        `xmlns:wsse11="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"> ` +
        `<wsse:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID">${assertionId}</wsse:KeyIdentifier>` +
        `</wsse:SecurityTokenReference>`
      );
    }

    const xml =
      '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"> ' +
      "<SOAP-ENV:Header> " +
      "<wsse:Security " +
      'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" ' +
      'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"> ' +
      "<Assertion></Assertion> " +
      "</wsse:Security> " +
      "</SOAP-ENV:Header> " +
      "</SOAP-ENV:Envelope>";

    const sig = new SignedXml();
    const assertionId = "_81d5fba5c807be9e9cf60c58566349b1";
    sig.getKeyInfoContent = getKeyInfoContentWithAssertionId.bind(this, { assertionId });
    sig.privateKey = fs.readFileSync("./test/static/client.pem");
    sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
    sig.signatureAlgorithm = SIGNATURE_ALGORITHMS.RSA_SHA1;
    sig.computeSignature(xml, {
      prefix: "ds",
      location: {
        reference: "//Assertion",
        action: "after",
      },
      existingPrefixes: {
        wsse: NAMESPACES.wsse,
        wsu: NAMESPACES.wsu,
      },
    });
    const result = sig.getSignedXml();
    expect((result.match(/xmlns:wsu=/g) || []).length).to.equal(1);
    expect((result.match(/xmlns:wsse=/g) || []).length).to.equal(1);
    expect(result.includes(assertionId)).to.be.true;
  });

  it("creates InclusiveNamespaces element when inclusiveNamespacesPrefixList is set on Reference", function () {
    const xml = "<root><x /></root>";
    const sig = new SignedXml();
    sig.privateKey = fs.readFileSync("./test/static/client.pem");

    sig.addReference({
      xpath: "//*[local-name(.)='root']",
      transforms: [XMLDSIG_URIS.TRANSFORM_ALGORITHMS.ENVELOPED_SIGNATURE],
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
      uri: "",
      digestValue: "",
      inclusiveNamespacesPrefixList: ["prefix1", "prefix2"],
    });

    sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
    sig.signatureAlgorithm = SIGNATURE_ALGORITHMS.RSA_SHA1;
    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    const doc = new xmldom.DOMParser().parseFromString(signedXml);
    const inclusiveNamespaces = xpath.select(
      "//*[local-name(.)='Reference']/*[local-name(.)='Transforms']/*[local-name(.)='Transform']/*[local-name(.)='InclusiveNamespaces']",
      doc.documentElement,
    );
    isDomNode.assertIsArrayOfNodes(inclusiveNamespaces);
    expect(inclusiveNamespaces.length, "InclusiveNamespaces element should exist").to.equal(1);

    const firstNamespace = inclusiveNamespaces[0];
    isDomNode.assertIsElementNode(firstNamespace);

    const prefixListAttribute = firstNamespace.getAttribute("PrefixList");
    expect(
      prefixListAttribute,
      "InclusiveNamespaces element should have the correct PrefixList attribute value",
    ).to.equal("prefix1 prefix2");
  });

  it("does not create InclusiveNamespaces element when inclusiveNamespacesPrefixList is not set on Reference", function () {
    const xml = "<root><x /></root>";
    const sig = new SignedXml();
    sig.privateKey = fs.readFileSync("./test/static/client.pem");

    sig.addReference({
      xpath: "//*[local-name(.)='root']",
      transforms: [XMLDSIG_URIS.TRANSFORM_ALGORITHMS.ENVELOPED_SIGNATURE],
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
      uri: "",
      digestValue: "",
      inclusiveNamespacesPrefixList: [],
    });

    sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
    sig.signatureAlgorithm = SIGNATURE_ALGORITHMS.RSA_SHA1;
    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    const doc = new xmldom.DOMParser().parseFromString(signedXml);
    const inclusiveNamespaces = xpath.select1(
      "//*[local-name(.)='Reference']/*[local-name(.)='Transforms']/*[local-name(.)='Transform']/*[local-name(.)='InclusiveNamespaces']",
      doc.documentElement,
    );

    expect(inclusiveNamespaces, "InclusiveNamespaces element should not exist").to.be.undefined;
  });

  it("creates InclusiveNamespaces element inside CanonicalizationMethod when inclusiveNamespacesPrefixList is set on SignedXml options", function () {
    const xml = "<root><x /></root>";
    const sig = new SignedXml({ inclusiveNamespacesPrefixList: "prefix1 prefix2" });
    sig.privateKey = fs.readFileSync("./test/static/client.pem");

    sig.addReference({
      xpath: "//*[local-name(.)='root']",
      transforms: [XMLDSIG_URIS.TRANSFORM_ALGORITHMS.ENVELOPED_SIGNATURE],
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
    });

    sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
    sig.signatureAlgorithm = SIGNATURE_ALGORITHMS.RSA_SHA1;
    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    const doc = new xmldom.DOMParser().parseFromString(signedXml);
    const inclusiveNamespaces = xpath.select(
      "//*[local-name(.)='CanonicalizationMethod']/*[local-name(.)='InclusiveNamespaces']",
      doc.documentElement,
    );

    isDomNode.assertIsArrayOfNodes(inclusiveNamespaces);

    expect(
      inclusiveNamespaces.length,
      "InclusiveNamespaces element should exist inside CanonicalizationMethod",
    ).to.equal(1);

    const firstNamespace = inclusiveNamespaces[0];
    isDomNode.assertIsElementNode(firstNamespace);

    const prefixListAttribute = firstNamespace.getAttribute("PrefixList");
    expect(
      prefixListAttribute,
      "InclusiveNamespaces element inside CanonicalizationMethod should have the correct PrefixList attribute value",
    ).to.equal("prefix1 prefix2");
  });

  it("does not create InclusiveNamespaces element inside CanonicalizationMethod when inclusiveNamespacesPrefixList is not set on SignedXml options", function () {
    const xml = "<root><x /></root>";
    const sig = new SignedXml(); // Omit inclusiveNamespacesPrefixList property
    sig.privateKey = fs.readFileSync("./test/static/client.pem");

    sig.addReference({
      xpath: "//*[local-name(.)='root']",
      transforms: [XMLDSIG_URIS.TRANSFORM_ALGORITHMS.ENVELOPED_SIGNATURE],
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
    });

    sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
    sig.signatureAlgorithm = SIGNATURE_ALGORITHMS.RSA_SHA1;
    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    const doc = new xmldom.DOMParser().parseFromString(signedXml);
    const inclusiveNamespaces = xpath.select1(
      "//*[local-name(.)='CanonicalizationMethod']/*[local-name(.)='InclusiveNamespaces']",
      doc.documentElement,
    );

    expect(
      inclusiveNamespaces,
      "InclusiveNamespaces element should not exist inside CanonicalizationMethod",
    ).to.be.undefined;
  });

  it("adds attributes to KeyInfo element when attrs are present in keyInfoProvider", function () {
    const xml = "<root><x /></root>";
    const sig = new SignedXml();
    sig.privateKey = fs.readFileSync("./test/static/client.pem");
    sig.keyInfoAttributes = {
      CustomUri: "http://www.example.com/keyinfo",
      CustomAttribute: "custom-value",
    };
    sig.getKeyInfoContent = () => "<dummy/>";

    sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
    sig.signatureAlgorithm = SIGNATURE_ALGORITHMS.RSA_SHA1;
    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    const doc = new xmldom.DOMParser().parseFromString(signedXml);
    const keyInfoElements = xpath.select("//*[local-name(.)='KeyInfo']", doc.documentElement);

    isDomNode.assertIsArrayOfNodes(keyInfoElements);
    expect(keyInfoElements.length, "KeyInfo element should exist").to.equal(1);
    const keyInfoElement = keyInfoElements[0];

    isDomNode.assertIsElementNode(keyInfoElement);
    const algorithmAttribute = keyInfoElement.getAttribute("CustomUri");
    expect(
      algorithmAttribute,
      "KeyInfo element should have the correct CustomUri attribute value",
    ).to.equal("http://www.example.com/keyinfo");

    const customAttribute = keyInfoElement.getAttribute("CustomAttribute");
    expect(
      customAttribute,
      "KeyInfo element should have the correct CustomAttribute attribute value",
    ).to.equal("custom-value");
  });

  it("adds all certificates and does not add private keys to KeyInfo element", function () {
    const xml = "<root><x /></root>";
    const sig = new SignedXml();
    const pemBuffer = fs.readFileSync("./test/static/client_bundle.pem");
    sig.privateKey = pemBuffer;
    sig.publicCert = pemBuffer;
    sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
    sig.signatureAlgorithm = SIGNATURE_ALGORITHMS.RSA_SHA1;
    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    const doc = new xmldom.DOMParser().parseFromString(signedXml);

    const x509certificates = xpath.select(
      "//*[local-name(.)='X509Certificate']",
      doc.documentElement,
    );
    isDomNode.assertIsArrayOfNodes(x509certificates);
    expect(x509certificates.length, "There should be exactly two certificates").to.equal(2);

    const cert1 = x509certificates[0];
    const cert2 = x509certificates[1];
    expect(cert1.textContent, "X509Certificate[0] TextContent does not exist").to.exist;
    expect(cert2.textContent, "X509Certificate[1] TextContent does not exist").to.exist;

    const trimmedTextContent1 = cert1.textContent?.trim();
    const trimmedTextContent2 = cert2.textContent?.trim();
    expect(trimmedTextContent1, "Empty certificate added [0]").to.not.be.empty;
    expect(trimmedTextContent2, "Empty certificate added [1]").to.not.be.empty;

    expect(trimmedTextContent1?.substring(0, 5), "Incorrect value for X509Certificate[0]").to.equal(
      "MIIDC",
    );
    expect(trimmedTextContent2?.substring(0, 5), "Incorrect value for X509Certificate[1]").to.equal(
      "MIIDZ",
    );
  });

  it("adds id and type attributes to Reference elements when provided", function () {
    const xml = "<root><x /></root>";
    const sig = new SignedXml();
    sig.privateKey = fs.readFileSync("./test/static/client.pem");

    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
      transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
      id: "ref-1",
      type: "http://www.w3.org/2000/09/xmldsig#Object",
    });

    sig.canonicalizationAlgorithm = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
    sig.signatureAlgorithm = SIGNATURE_ALGORITHMS.RSA_SHA1;
    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    const doc = new xmldom.DOMParser().parseFromString(signedXml);
    const referenceElements = xpath.select("//*[local-name(.)='Reference']", doc);
    isDomNode.assertIsArrayOfNodes(referenceElements);
    expect(referenceElements.length, "Reference element should exist").to.equal(1);

    const referenceElement = referenceElements[0];
    isDomNode.assertIsElementNode(referenceElement);

    const idAttribute = referenceElement.getAttribute("Id");
    expect(idAttribute, "Reference element should have the correct Id attribute value").to.equal(
      "ref-1",
    );

    const typeAttribute = referenceElement.getAttribute("Type");
    expect(
      typeAttribute,
      "Reference element should have the correct Type attribute value",
    ).to.equal("http://www.w3.org/2000/09/xmldsig#Object");
  });

  it("should throw if xpath matches no nodes", () => {
    const sig = new SignedXml({
      privateKey: fs.readFileSync("./test/static/client.pem"),
      canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      signatureAlgorithm: XMLDSIG_URIS.SIGNATURE_ALGORITHMS.RSA_SHA256,
    });

    sig.addReference({
      xpath: "//definitelyNotThere",
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
      transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    expect(() => sig.computeSignature("<root></root>")).to.throw(
      /the following xpath cannot be signed because it was not found/,
    );
  });

  it("should sign references when the Id attribute is prefixed", () => {
    const xml = '<root><x xmlns:ns="urn:example" ns:Id="unique-id"/></root>';
    const sig = new SignedXml({
      privateKey: fs.readFileSync("./test/static/client.pem"),
      canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
      signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA1,
    });

    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: HASH_ALGORITHMS.SHA1,
      transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    const doc = new xmldom.DOMParser().parseFromString(signedXml);
    const referenceElements = xpath.select("//*[local-name(.)='Reference']", doc);
    isDomNode.assertIsArrayOfNodes(referenceElements);
    expect(referenceElements.length, "Reference element should exist").to.equal(1);

    const referenceElement = referenceElements[0];
    isDomNode.assertIsElementNode(referenceElement);

    const uriAttribute = referenceElement.getAttribute("URI");
    expect(uriAttribute, "Reference element should have the correct URI attribute value").to.equal(
      "#unique-id",
    );
  });
});
