import * as fs from "fs";
import { expect } from "chai";
import { XmlDSigVerifier, SignedXml, ExclusiveCanonicalization } from "../src";
import { RsaSha1 } from "../src/signature-algorithms";
import { Sha1 } from "../src/hash-algorithms";
import { EnvelopedSignature } from "../src/enveloped-signature";
import { XMLDSIG_URIS, XmlDsigVerificationResult } from "../src/";

import { X509Certificate } from "node:crypto";

// Parse the XML and get both signature nodes
import { DOMParser } from "@xmldom/xmldom";

const {
  CANONICALIZATION_ALGORITHMS,
  DIGEST_ALGORITHMS,
  SIGNATURE_ALGORITHMS,
  TRANSFORM_ALGORITHMS,
} = XMLDSIG_URIS;

// Default test certificate files
const privateKey = fs.readFileSync("./test/static/client.pem", "utf-8");
const publicCert = fs.readFileSync("./test/static/client_public.pem", "utf-8");

// Chain certificate files for truststore testing
const chainPrivateKey = fs.readFileSync("./test/static/chain_client.key.pem", "utf-8");
const chainPublicCert = fs.readFileSync("./test/static/chain_client.crt.pem", "utf-8");
const rootCert = fs.readFileSync("./test/static/chain_root.crt.pem", "utf-8");

// Expired certificate for testing certificate expiration validation
const expiredKey = fs.readFileSync("./test/static/expired_certificate.key.pem", "utf-8");
const expiredCert = fs.readFileSync("./test/static/expired_certificate.crt.pem", "utf-8");

// Future certificate for testing certificate validity period validation
const futureKey = fs.readFileSync("./test/static/future_certificate.key.pem", "utf-8");
const futureCert = fs.readFileSync("./test/static/future_certificate.crt.pem", "utf-8");

// Helper function to create a signed XML document
function createSignedXml(
  xml: string,
  options: { prefix?: string; attrs?: Record<string, string> } = {},
): string {
  const sig = new SignedXml({
    privateKey,
    canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
    signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA1,
  });

  sig.addReference({
    xpath: "//*[local-name(.)='test']",
    digestAlgorithm: DIGEST_ALGORITHMS.SHA1,
    transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
  });

  sig.computeSignature(xml, options);
  return sig.getSignedXml();
}

// Helper function to create a signed XML document for truststore testing
function createChainSignedXml(xml: string): string {
  const sig = new SignedXml({
    privateKey: chainPrivateKey,
    canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
    signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA1,
    getKeyInfoContent: () => SignedXml.getKeyInfoContent({ publicCert: chainPublicCert }),
  });

  sig.addReference({
    xpath: "//*[local-name(.)='test']",
    digestAlgorithm: DIGEST_ALGORITHMS.SHA1,
    transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
  });

  sig.computeSignature(xml);
  return sig.getSignedXml();
}

function createExpiredSignedXml(xml: string): string {
  const sig = new SignedXml({
    privateKey: expiredKey,
    canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
    signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA1,
    getKeyInfoContent: () => SignedXml.getKeyInfoContent({ publicCert: expiredCert }),
  });

  sig.addReference({
    xpath: "//*[local-name(.)='test']",
    digestAlgorithm: DIGEST_ALGORITHMS.SHA1,
    transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
  });

  sig.computeSignature(xml);
  return sig.getSignedXml();
}

function createFutureSignedXml(xml: string): string {
  const sig = new SignedXml({
    privateKey: futureKey,
    canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
    signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA1,
    getKeyInfoContent: () => SignedXml.getKeyInfoContent({ publicCert: futureCert }),
  });

  sig.addReference({
    xpath: "//*[local-name(.)='test']",
    digestAlgorithm: DIGEST_ALGORITHMS.SHA1,
    transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
  });

  sig.computeSignature(xml);
  return sig.getSignedXml();
}

function expectValidResult(result: XmlDsigVerificationResult, references: number = 1) {
  expect(result.success).to.be.true;
  expect(result.error).to.be.undefined;
  expect(result.signedReferences).to.be.an("array");
  expect(result.signedReferences).to.have.length(references);
}

function expectInvalidResult(result: XmlDsigVerificationResult, errorMessage?: string) {
  expect(result.success).to.be.false;
  expect(result.signedReferences).to.be.undefined;
  expect(result.error).to.be.a("string");
  if (errorMessage && result.error) {
    expect(result.error.toLowerCase()).to.contain(errorMessage.toLowerCase());
  }
}

describe("XmlDSigVerifier", function () {
  const xml = "<root><test>content</test></root>";

  describe("constructor", function () {
    it("should create verifier with public certificate", function () {
      const verifier = new XmlDSigVerifier({
        keySelector: { publicCert },
      });
      expect(verifier).to.be.instanceOf(XmlDSigVerifier);
    });

    it("should create verifier with getCertFromKeyInfo function", function () {
      const verifier = new XmlDSigVerifier({
        keySelector: {
          getCertFromKeyInfo: () => publicCert,
        },
      });
      expect(verifier).to.be.instanceOf(XmlDSigVerifier);
    });

    it("should throw when trying to create a verifier without publicCert or getCertFromKeyInfo", function () {
      expect(() => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new XmlDSigVerifier({ keySelector: {} as any });
      }).to.throw(
        "XmlDSigVerifier requires a valid keySelector option with either a publicCert or getCertFromKeyInfo function set.",
      );
    });

    it("should create verifier with all options set", function () {
      const verifier = new XmlDSigVerifier({
        keySelector: { publicCert },
        idAttributes: ["customId"],
        implicitTransforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
        throwOnError: true,
        security: {
          maxTransforms: 5,
          checkCertExpiration: true,
          truststore: [rootCert],
          signatureAlgorithms: SignedXml.getDefaultSignatureAlgorithms(),
          hashAlgorithms: SignedXml.getDefaultDigestAlgorithms(),
          transformAlgorithms: SignedXml.getDefaultTransformAlgorithms(),
        },
      });
      expect(verifier).to.be.instanceOf(XmlDSigVerifier);
    });

    it("should throw when getCertFromKeyInfo is undefined", function () {
      expect(() => {
        new XmlDSigVerifier({
          keySelector: {
            getCertFromKeyInfo: undefined as never,
          },
        });
      }).to.throw("XmlDSigVerifier requires a valid getCertFromKeyInfo function in options.");
    });

    it("should throw when getCertFromKeyInfo is set to publicCert string directly", function () {
      expect(() => {
        new XmlDSigVerifier({
          keySelector: {
            getCertFromKeyInfo: publicCert as never,
          },
        });
      }).to.throw("XmlDSigVerifier requires a valid getCertFromKeyInfo function in options.");
    });
  });

  describe("publicCert selector", function () {
    it("should validate a valid signed XML document", function () {
      const signedXml = createSignedXml(xml);

      const verifier = new XmlDSigVerifier({
        keySelector: { publicCert },
      });
      expectValidResult(verifier.verifySignature(signedXml));
    });

    it("should validate when publicCert is a buffer", function () {
      const signedXml = createSignedXml(xml);

      const verifier = new XmlDSigVerifier({
        keySelector: { publicCert: Buffer.from(publicCert) },
      });
      expectValidResult(verifier.verifySignature(signedXml));
    });

    it("should fail validation when document is signed with different key", function () {
      const signedXml = createChainSignedXml(xml);

      const verifier = new XmlDSigVerifier({
        keySelector: { publicCert },
        throwOnError: false,
      });

      expectInvalidResult(verifier.verifySignature(signedXml), "invalid signature");
    });
  });

  describe("getCertFromKeyInfo selector", function () {
    it("should validate a valid signed XML document", function () {
      const signedXml = createSignedXml(xml);

      const verifier = new XmlDSigVerifier({
        keySelector: {
          getCertFromKeyInfo: () => publicCert,
        },
      });
      expectValidResult(verifier.verifySignature(signedXml));
    });

    it("should fail validation when document is signed with different key", function () {
      const signedXml = createChainSignedXml(xml);

      const verifier = new XmlDSigVerifier({
        keySelector: {
          getCertFromKeyInfo: () => publicCert,
        },
        throwOnError: false,
      });

      expectInvalidResult(verifier.verifySignature(signedXml), "invalid signature");
    });

    it("should fail validation when getCertFromKeyInfo returns null", function () {
      const signedXml = createSignedXml(xml);

      const verifier = new XmlDSigVerifier({
        keySelector: {
          getCertFromKeyInfo: () => null,
        },
        throwOnError: false,
      });

      expectInvalidResult(verifier.verifySignature(signedXml), "keyinfo");
    });

    it("should fail validation when getCertFromKeyInfo returns empty string", function () {
      const signedXml = createSignedXml(xml);

      const verifier = new XmlDSigVerifier({
        keySelector: {
          getCertFromKeyInfo: () => "",
        },
        throwOnError: false,
      });

      expectInvalidResult(verifier.verifySignature(signedXml), "keyinfo");
    });
  });

  describe("idAttributes option", function () {
    const xmlWithCustomId = '<root><test customId="test1">content</test></root>';
    const xmlWithPrefixedId = `<root xmlns:foo="uri:foo"><test foo:customId="test1">content</test></root>`;

    it("should validate a valid signed XML document with custom Id", function () {
      const sig = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
        signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA1,
        idAttributes: ["customId"],
      });
      sig.addReference({
        xpath: "//*[@customId='test1']",
        digestAlgorithm: DIGEST_ALGORITHMS.SHA1,
        transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
      });
      sig.computeSignature(xmlWithCustomId);
      const signedXml = sig.getSignedXml();

      const verifier = new XmlDSigVerifier({
        keySelector: { publicCert },
        idAttributes: ["customId"],
      });
      expectValidResult(verifier.verifySignature(signedXml));
    });

    it("should validate a valid signed XML document with prefixed Id", function () {
      const sig = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
        signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA1,
        idAttributes: ["customId"],
      });
      sig.addReference({
        xpath: "//*[@*[namespace-uri() = 'uri:foo' and local-name() = 'customId']]",
        digestAlgorithm: DIGEST_ALGORITHMS.SHA1,
        transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
      });
      sig.computeSignature(xmlWithPrefixedId);
      const signedXml = sig.getSignedXml();

      const verifier = new XmlDSigVerifier({
        keySelector: { publicCert },
        idAttributes: ["customId"],
      });
      expectValidResult(verifier.verifySignature(signedXml));
    });

    it("should work with explicitly namespaced Id attributes", function () {
      const sig = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
        signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA1,
        idAttributes: ["customId"],
      });
      sig.addReference({
        xpath: "//*[@*[namespace-uri() = 'uri:foo' and local-name() = 'customId']]",
        digestAlgorithm: DIGEST_ALGORITHMS.SHA1,
        transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
      });
      sig.computeSignature(xmlWithPrefixedId);
      const signedXml = sig.getSignedXml();

      const verifier = new XmlDSigVerifier({
        keySelector: { publicCert },
        idAttributes: [{ localName: "customId", namespaceUri: "uri:foo" }],
      });
      expectValidResult(verifier.verifySignature(signedXml));
    });

    it("should fail validation when Id attribute is not in the correct namespace", function () {
      const sig = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
        signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA1,
        idAttributes: ["customId"],
      });
      sig.addReference({
        xpath: "//*[@*[namespace-uri() = 'uri:foo' and local-name() = 'customId']]",
        digestAlgorithm: DIGEST_ALGORITHMS.SHA1,
        transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
      });
      sig.computeSignature(xmlWithPrefixedId);
      const signedXml = sig.getSignedXml();

      const verifier = new XmlDSigVerifier({
        keySelector: { publicCert },
        idAttributes: [{ localName: "customId", namespaceUri: "uri:bar" }],
        throwOnError: false,
      });
      expectInvalidResult(verifier.verifySignature(signedXml), "fail");
    });

    it("should fail validation when Id attribute is not namespaced but namespaceUri is provided", function () {
      const sig = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
        signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA1,
        idAttributes: ["customId"],
      });
      sig.addReference({
        xpath: "//*[@customId='test1']",
        digestAlgorithm: DIGEST_ALGORITHMS.SHA1,
        transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
      });
      sig.computeSignature(xmlWithCustomId);
      const signedXml = sig.getSignedXml();

      const verifier = new XmlDSigVerifier({
        keySelector: { publicCert },
        idAttributes: [{ localName: "customId", namespaceUri: "uri:foo" }],
        throwOnError: false,
      });
      expectInvalidResult(verifier.verifySignature(signedXml), "fail");
    });
  });

  describe("throwOnError option", function () {
    it("should throw validation errors when throwOnError is true", function () {
      const signedXml = createSignedXml(xml);
      const tamperedXml = signedXml.replace("content", "tampered");

      const verifier = new XmlDSigVerifier({
        keySelector: { publicCert },
        throwOnError: true,
      });

      expect(() => verifier.verifySignature(tamperedXml)).to.throw("verification failed");
    });

    it("should return error details when throwOnError is false", function () {
      const signedXml = createSignedXml(xml);
      const tamperedXml = signedXml.replace("content", "tampered");

      const verifier = new XmlDSigVerifier({
        keySelector: { publicCert },
        throwOnError: false,
      });

      const result = verifier.verifySignature(tamperedXml);
      expectInvalidResult(result, "verification failed");
    });
  });

  describe("security options", function () {
    describe("maxTransforms", function () {
      it("should validate when number of transforms is within maxTransforms", function () {
        const signedXml = createSignedXml(xml);
        const verifier = new XmlDSigVerifier({
          keySelector: { publicCert },
          security: { maxTransforms: 1 },
        });
        expectValidResult(verifier.verifySignature(signedXml));
      });

      it("should fail validation when number of transforms exceeds maxTransforms", function () {
        const sig = new SignedXml({
          privateKey,
          canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
          signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA1,
        });
        sig.addReference({
          xpath: "//*[local-name(.)='test']",
          digestAlgorithm: DIGEST_ALGORITHMS.SHA1,
          transforms: [
            CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
            TRANSFORM_ALGORITHMS.ENVELOPED_SIGNATURE,
          ],
        });
        sig.computeSignature(xml);
        const signedXml = sig.getSignedXml();
        const verifier = new XmlDSigVerifier({
          keySelector: { publicCert },
          security: { maxTransforms: 1 },
        });
        expectInvalidResult(verifier.verifySignature(signedXml), "exceeds the maximum allowed");
      });
    });

    describe("checkCertExpiration", function () {
      it("should validate when certificate is not expired and checkCertExpiration is true", function () {
        const signedXml = createSignedXml(xml);
        const verifier = new XmlDSigVerifier({
          keySelector: { publicCert },
          security: { checkCertExpiration: true },
        });
        expectValidResult(verifier.verifySignature(signedXml));
      });

      it("should validate when certificate is expired and checkCertExpiration is false", function () {
        const signedXml = createExpiredSignedXml(xml);
        const verifier = new XmlDSigVerifier({
          keySelector: { publicCert: expiredCert },
          security: { checkCertExpiration: false },
        });
        expectValidResult(verifier.verifySignature(signedXml));
      });

      it("should fail validation when certificate is expired and checkCertExpiration is true", function () {
        const signedXml = createExpiredSignedXml(xml);
        const verifier = new XmlDSigVerifier({
          keySelector: { getCertFromKeyInfo: () => expiredCert },
          security: { checkCertExpiration: true },
        });
        expectInvalidResult(verifier.verifySignature(signedXml), "expired");
      });

      it("should fail validation when certificate is not yet valid and checkCertExpiration is true", function () {
        const signedXml = createFutureSignedXml(xml);
        const verifier = new XmlDSigVerifier({
          keySelector: { getCertFromKeyInfo: () => futureCert },
          security: { checkCertExpiration: true },
        });
        expectInvalidResult(verifier.verifySignature(signedXml), "not yet valid");
      });
    });

    describe("truststore", function () {
      it("should validate when certificate is exactly in truststore", function () {
        const signedXml = createSignedXml(xml);
        const verifier = new XmlDSigVerifier({
          keySelector: { getCertFromKeyInfo: () => publicCert },
          security: { truststore: [publicCert] },
        });

        expectValidResult(verifier.verifySignature(signedXml));
      });

      it("should validate when certificate is trusted", function () {
        const signedXml = createChainSignedXml(xml);
        const verifier = new XmlDSigVerifier({
          keySelector: { getCertFromKeyInfo: () => chainPublicCert },
          security: { truststore: [rootCert] },
        });

        expectValidResult(verifier.verifySignature(signedXml));
      });

      it("should validate when X509Certificate is directly passed into truststore", function () {
        const signedXml = createChainSignedXml(xml);
        const rootX509 = new X509Certificate(rootCert);

        const verifier = new XmlDSigVerifier({
          keySelector: { getCertFromKeyInfo: () => chainPublicCert },
          security: { truststore: [rootX509] },
        });

        expectValidResult(verifier.verifySignature(signedXml));
      });

      it("should fail validation when certificate is not trusted", function () {
        const signedXml = createSignedXml(xml);
        const verifier = new XmlDSigVerifier({
          keySelector: { getCertFromKeyInfo: () => publicCert },
          security: { truststore: [rootCert] },
        });
        expectInvalidResult(verifier.verifySignature(signedXml), "not trusted");
      });

      it("should validate truststore even when checkCertExpiration is false", function () {
        const signedXml = createChainSignedXml(xml);
        const verifier = new XmlDSigVerifier({
          keySelector: { getCertFromKeyInfo: () => chainPublicCert },
          security: {
            checkCertExpiration: false,
            truststore: [rootCert],
          },
        });
        expectValidResult(verifier.verifySignature(signedXml));
      });

      it("should validate when checkCertExpiration is false and no truststore is provided", function () {
        const signedXml = createSignedXml(xml);
        const verifier = new XmlDSigVerifier({
          keySelector: { getCertFromKeyInfo: () => publicCert },
          security: {
            checkCertExpiration: false,
            truststore: [],
          },
        });
        expectValidResult(verifier.verifySignature(signedXml));
      });
    });

    describe("signatureAlgorithms", function () {
      it("should validate when signature algorithm is allowed", function () {
        const signedXml = createSignedXml(xml);
        const verifier = new XmlDSigVerifier({
          keySelector: { publicCert },
          security: { signatureAlgorithms: SignedXml.getDefaultSignatureAlgorithms() },
        });
        expectValidResult(verifier.verifySignature(signedXml));
      });

      it("should fail validation when signature algorithm is not allowed", function () {
        const signedXml = createSignedXml(xml);
        const verifier = new XmlDSigVerifier({
          keySelector: { publicCert },
          security: { signatureAlgorithms: { foo: RsaSha1 } },
        });
        expectInvalidResult(verifier.verifySignature(signedXml), "signature algorithm");
      });
    });

    describe("hashAlgorithms", function () {
      it("should validate when hash algorithm is allowed", function () {
        const signedXml = createSignedXml(xml);
        const verifier = new XmlDSigVerifier({
          keySelector: { publicCert },
          security: { hashAlgorithms: SignedXml.getDefaultDigestAlgorithms() },
        });
        expectValidResult(verifier.verifySignature(signedXml));
      });

      it("should fail validation when hash algorithm is not allowed", function () {
        const signedXml = createSignedXml(xml);
        const verifier = new XmlDSigVerifier({
          keySelector: { publicCert },
          security: { hashAlgorithms: { foo: Sha1 } },
        });
        expectInvalidResult(verifier.verifySignature(signedXml), "hash algorithm");
      });
    });

    describe("transformAlgorithms", function () {
      it("should validate when transform algorithms are allowed", function () {
        const signedXml = createSignedXml(xml);
        const verifier = new XmlDSigVerifier({
          keySelector: { publicCert },
          security: { transformAlgorithms: SignedXml.getDefaultTransformAlgorithms() },
        });
        expectValidResult(verifier.verifySignature(signedXml));
      });

      it("should fail validation when a transform algorithm is not allowed", function () {
        const signedXml = createSignedXml(xml);
        const verifier = new XmlDSigVerifier({
          keySelector: { publicCert },
          security: { transformAlgorithms: { foo: EnvelopedSignature } },
        });
        expectInvalidResult(verifier.verifySignature(signedXml), "transform algorithm");
      });
    });

    describe("canonicalizationAlgorithms", function () {
      it("should validate when canonicalization algorithms are allowed", function () {
        const signedXml = createSignedXml(xml);
        const verifier = new XmlDSigVerifier({
          keySelector: { publicCert },
          security: {
            canonicalizationAlgorithms: SignedXml.getDefaultCanonicalizationAlgorithms(),
          },
        });
        expectValidResult(verifier.verifySignature(signedXml));
      });

      it("should fail validation when a canonicalization algorithm is not allowed", function () {
        const signedXml = createSignedXml(xml);
        const verifier = new XmlDSigVerifier({
          keySelector: { publicCert },
          security: { canonicalizationAlgorithms: { foo: ExclusiveCanonicalization } },
        });
        expectInvalidResult(verifier.verifySignature(signedXml), "canonicalization algorithm");
      });
    });
  });

  describe("signatureNode parameter", function () {
    it("should fail when XML has no signatures", function () {
      const unsignedXml = "<root><test>content</test></root>";

      const verifier = new XmlDSigVerifier({
        keySelector: { publicCert },
        throwOnError: false,
      });

      const result = verifier.verifySignature(unsignedXml);
      expectInvalidResult(result, "No Signature element found");
    });

    it("should validate when signatureNode is provided directly", function () {
      const signedXml = createSignedXml(xml);
      const doc = new DOMParser().parseFromString(signedXml, "application/xml");
      const signatureNode = doc.getElementsByTagNameNS(
        "http://www.w3.org/2000/09/xmldsig#",
        "Signature",
      )[0];

      const verifier = new XmlDSigVerifier({
        keySelector: { publicCert },
      });

      const result = verifier.verifySignature(signedXml, signatureNode);
      expectValidResult(result);
    });

    it("should fail when XML has multiple signatures but no signatureNode is specified", function () {
      // Create XML with two different test elements
      const xmlWithTwoElements =
        "<root><test id='1'>content1</test><test id='2'>content2</test></root>";

      // Create first signature for first test element
      const sig1 = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
        signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA1,
      });
      sig1.addReference({
        xpath: "//*[@id='1']",
        digestAlgorithm: DIGEST_ALGORITHMS.SHA1,
        transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
      });
      sig1.computeSignature(xmlWithTwoElements, {
        location: { reference: "/root", action: "append" },
      });
      const xmlWithFirstSig = sig1.getSignedXml();

      // Create second signature for second test element
      const sig2 = new SignedXml({
        privateKey: chainPrivateKey,
        canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
        signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA1,
      });
      sig2.addReference({
        xpath: "//*[@id='2']",
        digestAlgorithm: DIGEST_ALGORITHMS.SHA1,
        transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
      });
      sig2.computeSignature(xmlWithFirstSig, {
        location: { reference: "/root", action: "append" },
      });
      const xmlWithTwoSigs = sig2.getSignedXml();

      const verifier = new XmlDSigVerifier({
        keySelector: { publicCert },
        throwOnError: false,
      });

      const result = verifier.verifySignature(xmlWithTwoSigs);
      expectInvalidResult(result, "Multiple Signature elements found");
    });

    it("should validate specific signature when XML has multiple signatures", function () {
      // Create XML with two different test elements
      const xmlWithTwoElements =
        "<root><test id='1'>content1</test><test id='2'>content2</test></root>";

      // Create first signature for first test element
      const sig1 = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
        signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA1,
      });
      sig1.addReference({
        xpath: "//*[@id='1']",
        digestAlgorithm: DIGEST_ALGORITHMS.SHA1,
        transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
      });
      sig1.computeSignature(xmlWithTwoElements, {
        location: { reference: "/root", action: "append" },
      });
      const xmlWithFirstSig = sig1.getSignedXml();

      // Create second signature for second test element
      const sig2 = new SignedXml({
        privateKey: chainPrivateKey, // Use different key for second signature
        canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
        signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA1,
      });
      sig2.addReference({
        xpath: "//*[@id='2']",
        digestAlgorithm: DIGEST_ALGORITHMS.SHA1,
        transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
      });
      sig2.computeSignature(xmlWithFirstSig, {
        location: { reference: "/root", action: "append" },
      });
      const xmlWithTwoSigs = sig2.getSignedXml();
      const doc = new DOMParser().parseFromString(xmlWithTwoSigs, "application/xml");
      const signatureNodes = doc.getElementsByTagNameNS(
        "http://www.w3.org/2000/09/xmldsig#",
        "Signature",
      );

      expect(signatureNodes.length).to.equal(2);

      // Verify first signature with first key
      const verifier1 = new XmlDSigVerifier({
        keySelector: { publicCert },
      });
      const result1 = verifier1.verifySignature(xmlWithTwoSigs, signatureNodes[0]);
      expectValidResult(result1);

      // Verify second signature with second key
      const verifier2 = new XmlDSigVerifier({
        keySelector: { publicCert: chainPublicCert },
      });
      const result2 = verifier2.verifySignature(xmlWithTwoSigs, signatureNodes[1]);
      expectValidResult(result2);
    });
  });

  describe("static verifySignature method", function () {
    it("should return success result when throwOnError is false and no error occurs", function () {
      const signedXml = createSignedXml(xml);

      const result = XmlDSigVerifier.verifySignature(signedXml, {
        keySelector: { publicCert },
        throwOnError: false,
      });

      expectValidResult(result);
    });

    it("should return error result when throwOnError is false and error occurs", function () {
      const signedXml = createSignedXml(xml);
      const tamperedXml = signedXml.replace("content", "tampered");

      const result = XmlDSigVerifier.verifySignature(tamperedXml, {
        keySelector: { publicCert },
        throwOnError: false,
      });

      expectInvalidResult(result, "verification failed");
    });

    it("should return success result when throwOnError is true and no error occurs", function () {
      const signedXml = createSignedXml(xml);

      const result = XmlDSigVerifier.verifySignature(signedXml, {
        keySelector: { publicCert },
        throwOnError: true,
      });

      expectValidResult(result);
    });

    it("should throw error when throwOnError is true and error occurs", function () {
      const signedXml = createSignedXml(xml);
      const tamperedXml = signedXml.replace("content", "tampered");

      expect(() => {
        XmlDSigVerifier.verifySignature(tamperedXml, {
          keySelector: { publicCert },
          throwOnError: true,
        });
      }).to.throw("verification failed");
    });

    it("should use default throwOnError (false) when not explicitly provided", function () {
      const result = XmlDSigVerifier.verifySignature("<root><test>content</test></root>", {
        keySelector: {
          getCertFromKeyInfo: null as never,
        },
      });

      expectInvalidResult(
        result,
        "XmlDSigVerifier requires a valid getCertFromKeyInfo function in options.",
      );
    });
  });
});
