import * as fs from "fs";
import { expect } from "chai";
import { XmlDSigValidator, SignedXml, Algorithms, ExclusiveCanonicalization } from "../src";
import { XmlDSigValidationResult } from "../src/xmldsig-validator";
import { RsaSha1 } from "../src/signature-algorithms";
import { Sha1 } from "../src/hash-algorithms";
import { EnvelopedSignature } from "../src/enveloped-signature";

const { canonicalization, hash, signature } = Algorithms;

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

// Helper function to create a signed XML document
function createSignedXml(
  xml: string,
  options: { prefix?: string; attrs?: Record<string, string> } = {},
): string {
  const sig = new SignedXml({
    privateKey,
    canonicalizationAlgorithm: canonicalization.EXCLUSIVE_C14N,
    signatureAlgorithm: signature.RSA_SHA1,
  });

  sig.addReference({
    xpath: "//*[local-name(.)='test']",
    digestAlgorithm: hash.SHA1,
    transforms: [canonicalization.EXCLUSIVE_C14N],
  });

  sig.computeSignature(xml, options);
  return sig.getSignedXml();
}

// Helper function to create a signed XML document for truststore testing
function createChainSignedXml(xml: string): string {
  const sig = new SignedXml({
    privateKey: chainPrivateKey,
    canonicalizationAlgorithm: canonicalization.EXCLUSIVE_C14N,
    signatureAlgorithm: signature.RSA_SHA1,
    getKeyInfoContent: () => SignedXml.getKeyInfoContent({ publicCert: chainPublicCert }),
  });

  sig.addReference({
    xpath: "//*[local-name(.)='test']",
    digestAlgorithm: hash.SHA1,
    transforms: [canonicalization.EXCLUSIVE_C14N],
  });

  sig.computeSignature(xml);
  return sig.getSignedXml();
}

function createExpiredSignedXml(xml: string): string {
  const sig = new SignedXml({
    privateKey: expiredKey,
    canonicalizationAlgorithm: canonicalization.EXCLUSIVE_C14N,
    signatureAlgorithm: signature.RSA_SHA1,
    getKeyInfoContent: () => SignedXml.getKeyInfoContent({ publicCert: expiredCert }),
  });

  sig.addReference({
    xpath: "//*[local-name(.)='test']",
    digestAlgorithm: hash.SHA1,
    transforms: [canonicalization.EXCLUSIVE_C14N],
  });

  sig.computeSignature(xml);
  return sig.getSignedXml();
}

function expectValidResult(result: XmlDSigValidationResult, references: number = 1) {
  expect(result.valid).to.be.true;
  expect(result.error).to.be.undefined;
  expect(result.signedReferences).to.be.an("array");
  expect(result.signedReferences).to.have.length(references);
}

function expectInvalidResult(result: XmlDSigValidationResult, errorMessage?: string) {
  expect(result.valid).to.be.false;
  expect(result.signedReferences).to.be.undefined;
  expect(result.error).to.be.a("string");
  if (errorMessage && result.error) {
    expect(result.error.toLowerCase()).to.contain(errorMessage.toLowerCase());
  }
}

describe("XmlDSigValidator", function () {
  const xml = "<root><test>content</test></root>";

  describe("constructor", function () {
    it("should create validator with public certificate", function () {
      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
      });
      expect(validator).to.be.instanceOf(XmlDSigValidator);
    });

    it("should create validator with getCertFromKeyInfo function", function () {
      const validator = new XmlDSigValidator({
        keySelector: {
          getCertFromKeyInfo: () => publicCert,
        },
      });
      expect(validator).to.be.instanceOf(XmlDSigValidator);
    });

    it("should throw when trying to create a validator without publicCert or getCertFromKeyInfo", function () {
      expect(() => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new XmlDSigValidator({ keySelector: {} as any });
      }).to.throw("XmlDSigValidator requires a keySelector in options.");
    });

    it("should create validator with all options set", function () {
      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
        idAttributes: ["customId"],
        implicitTransforms: [canonicalization.EXCLUSIVE_C14N],
        throwOnError: true,
        security: {
          maxTransforms: 5,
          checkCertExpiration: true,
          truststore: [rootCert],
          signatureAlgorithms: SignedXml.getDefaultSignatureAlgorithms(),
          hashAlgorithms: SignedXml.getDefaultHashAlgorithms(),
          transformAlgorithms: SignedXml.getDefaultTransformAlgorithms(),
        },
      });
      expect(validator).to.be.instanceOf(XmlDSigValidator);
    });
  });

  describe("publicCert selector", function () {
    it("should validate a valid signed XML document", function () {
      const signedXml = createSignedXml(xml);

      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
      });
      expectValidResult(validator.validate(signedXml));
    });

    it("should validate when publicCert is a buffer", function () {
      const signedXml = createSignedXml(xml);

      const validator = new XmlDSigValidator({
        keySelector: { publicCert: Buffer.from(publicCert) },
      });
      expectValidResult(validator.validate(signedXml));
    });

    it("should fail validation when document is signed with different key", function () {
      const signedXml = createChainSignedXml(xml);

      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
        throwOnError: false,
      });

      expectInvalidResult(validator.validate(signedXml), "invalid signature");
    });
  });

  describe("getCertFromKeyInfo selector", function () {
    it("should validate a valid signed XML document", function () {
      const signedXml = createSignedXml(xml);

      const validator = new XmlDSigValidator({
        keySelector: {
          getCertFromKeyInfo: () => publicCert,
        },
      });
      expectValidResult(validator.validate(signedXml));
    });

    it("should fail validation when document is signed with different key", function () {
      const signedXml = createChainSignedXml(xml);

      const validator = new XmlDSigValidator({
        keySelector: {
          getCertFromKeyInfo: () => publicCert,
        },
        throwOnError: false,
      });

      expectInvalidResult(validator.validate(signedXml), "invalid signature");
    });
  });

  describe("idAttributes option", function () {
    const xmlWithCustomId = '<root><test customId="test1">content</test></root>';
    const xmlWithPrefixedId = `<root xmlns:foo="uri:foo"><test foo:customId="test1">content</test></root>`;

    it("should validate a valid signed XML document with custom Id", function () {
      const sig = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: canonicalization.EXCLUSIVE_C14N,
        signatureAlgorithm: signature.RSA_SHA1,
        idAttributes: ["customId"],
      });
      sig.addReference({
        xpath: "//*[@customId='test1']",
        digestAlgorithm: hash.SHA1,
        transforms: [canonicalization.EXCLUSIVE_C14N],
      });
      sig.computeSignature(xmlWithCustomId);
      const signedXml = sig.getSignedXml();

      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
        idAttributes: ["customId"],
      });
      expectValidResult(validator.validate(signedXml));
    });

    it("should validate a valid signed XML document with prefixed Id", function () {
      const sig = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: canonicalization.EXCLUSIVE_C14N,
        signatureAlgorithm: signature.RSA_SHA1,
        idAttributes: ["customId"],
      });
      sig.addReference({
        xpath: "//*[@*[namespace-uri() = 'uri:foo' and local-name() = 'customId']]",
        digestAlgorithm: hash.SHA1,
        transforms: [canonicalization.EXCLUSIVE_C14N],
      });
      sig.computeSignature(xmlWithPrefixedId);
      const signedXml = sig.getSignedXml();

      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
        idAttributes: ["customId"],
      });
      expectValidResult(validator.validate(signedXml));
    });

    it("should work with explicitly namespaced Id attributes", function () {
      const sig = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: canonicalization.EXCLUSIVE_C14N,
        signatureAlgorithm: signature.RSA_SHA1,
        idAttributes: ["customId"],
      });
      sig.addReference({
        xpath: "//*[@*[namespace-uri() = 'uri:foo' and local-name() = 'customId']]",
        digestAlgorithm: hash.SHA1,
        transforms: [canonicalization.EXCLUSIVE_C14N],
      });
      sig.computeSignature(xmlWithPrefixedId);
      const signedXml = sig.getSignedXml();

      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
        idAttributes: [{ localName: "customId", namespaceUri: "uri:foo" }],
      });
      expectValidResult(validator.validate(signedXml));
    });

    it("should fail validation when Id attribute is not in the correct namespace", function () {
      const sig = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: canonicalization.EXCLUSIVE_C14N,
        signatureAlgorithm: signature.RSA_SHA1,
        idAttributes: ["customId"],
      });
      sig.addReference({
        xpath: "//*[@*[namespace-uri() = 'uri:foo' and local-name() = 'customId']]",
        digestAlgorithm: hash.SHA1,
        transforms: [canonicalization.EXCLUSIVE_C14N],
      });
      sig.computeSignature(xmlWithPrefixedId);
      const signedXml = sig.getSignedXml();

      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
        idAttributes: [{ localName: "customId", namespaceUri: "uri:bar" }],
        throwOnError: false,
      });
      expectInvalidResult(validator.validate(signedXml), "fail");
    });

    it("should fail validation when Id attribute is not namespaced but namespaceUri is provided", function () {
      const sig = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: canonicalization.EXCLUSIVE_C14N,
        signatureAlgorithm: signature.RSA_SHA1,
        idAttributes: ["customId"],
      });
      sig.addReference({
        xpath: "//*[@customId='test1']",
        digestAlgorithm: hash.SHA1,
        transforms: [canonicalization.EXCLUSIVE_C14N],
      });
      sig.computeSignature(xmlWithCustomId);
      const signedXml = sig.getSignedXml();

      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
        idAttributes: [{ localName: "customId", namespaceUri: "uri:foo" }],
        throwOnError: false,
      });
      expectInvalidResult(validator.validate(signedXml), "fail");
    });
  });

  describe("throwOnError option", function () {
    it("should throw validation errors when throwOnError is true", function () {
      const signedXml = createSignedXml(xml);
      const tamperedXml = signedXml.replace("content", "tampered");

      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
        throwOnError: true,
      });

      expect(() => validator.validate(tamperedXml)).to.throw("Signature validation failed");
    });

    it("should return error details when throwOnError is false", function () {
      const signedXml = createSignedXml(xml);
      const tamperedXml = signedXml.replace("content", "tampered");

      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
        throwOnError: false,
      });

      const result = validator.validate(tamperedXml);
      expectInvalidResult(result, "Signature validation failed");
    });
  });

  describe("security options", function () {
    describe("maxTransforms", function () {
      it("should validate when number of transforms is within maxTransforms", function () {
        const signedXml = createSignedXml(xml);
        const validator = new XmlDSigValidator({
          keySelector: { publicCert },
          security: { maxTransforms: 1 },
        });
        expectValidResult(validator.validate(signedXml));
      });

      it("should fail validation when number of transforms exceeds maxTransforms", function () {
        const sig = new SignedXml({
          privateKey,
          canonicalizationAlgorithm: canonicalization.EXCLUSIVE_C14N,
          signatureAlgorithm: signature.RSA_SHA1,
        });
        sig.addReference({
          xpath: "//*[local-name(.)='test']",
          digestAlgorithm: hash.SHA1,
          transforms: [canonicalization.EXCLUSIVE_C14N, Algorithms.transform.ENVELOPED_SIGNATURE],
        });
        sig.computeSignature(xml);
        const signedXml = sig.getSignedXml();
        const validator = new XmlDSigValidator({
          keySelector: { publicCert },
          security: { maxTransforms: 1 },
        });
        expectInvalidResult(validator.validate(signedXml), "exceeds the maximum allowed");
      });
    });

    describe("checkCertExpiration", function () {
      it("should validate when certificate is not expired and checkCertExpiration is true", function () {
        const signedXml = createSignedXml(xml);
        const validator = new XmlDSigValidator({
          keySelector: { publicCert },
          security: { checkCertExpiration: true },
        });
        expectValidResult(validator.validate(signedXml));
      });

      it("should validate when certificate is expired and checkCertExpiration is false", function () {
        const signedXml = createExpiredSignedXml(xml);
        const validator = new XmlDSigValidator({
          keySelector: { publicCert: expiredCert },
          security: { checkCertExpiration: false },
        });
        expectValidResult(validator.validate(signedXml));
      });

      it("should fail validation when certificate is expired and checkCertExpiration is true", function () {
        const signedXml = createExpiredSignedXml(xml);
        const validator = new XmlDSigValidator({
          keySelector: { getCertFromKeyInfo: () => expiredCert },
          security: { checkCertExpiration: true },
        });
        expectInvalidResult(validator.validate(signedXml), "expired");
      });
    });

    describe("truststore", function () {
      it("should validate when certificate is exactly in truststore", function () {
        const signedXml = createSignedXml(xml);
        const validator = new XmlDSigValidator({
          keySelector: { getCertFromKeyInfo: () => publicCert },
          security: { truststore: [publicCert] },
        });

        expectValidResult(validator.validate(signedXml));
      });

      it("should validate when certificate is trusted", function () {
        const signedXml = createChainSignedXml(xml);
        const validator = new XmlDSigValidator({
          keySelector: { getCertFromKeyInfo: () => chainPublicCert },
          security: { truststore: [rootCert] },
        });

        expectValidResult(validator.validate(signedXml));
      });

      it("should fail validation when certificate is not trusted", function () {
        const signedXml = createSignedXml(xml);
        const validator = new XmlDSigValidator({
          keySelector: { getCertFromKeyInfo: () => publicCert },
          security: { truststore: [rootCert] },
        });
        expectInvalidResult(validator.validate(signedXml), "not trusted");
      });
    });

    describe("signatureAlgorithms", function () {
      it("should validate when signature algorithm is allowed", function () {
        const signedXml = createSignedXml(xml);
        const validator = new XmlDSigValidator({
          keySelector: { publicCert },
          security: { signatureAlgorithms: SignedXml.getDefaultSignatureAlgorithms() },
        });
        expectValidResult(validator.validate(signedXml));
      });

      it("should fail validation when signature algorithm is not allowed", function () {
        const signedXml = createSignedXml(xml);
        const validator = new XmlDSigValidator({
          keySelector: { publicCert },
          security: { signatureAlgorithms: { foo: RsaSha1 } },
        });
        expectInvalidResult(validator.validate(signedXml), "signature algorithm");
      });
    });

    describe("hashAlgorithms", function () {
      it("should validate when hash algorithm is allowed", function () {
        const signedXml = createSignedXml(xml);
        const validator = new XmlDSigValidator({
          keySelector: { publicCert },
          security: { hashAlgorithms: SignedXml.getDefaultHashAlgorithms() },
        });
        expectValidResult(validator.validate(signedXml));
      });

      it("should fail validation when hash algorithm is not allowed", function () {
        const signedXml = createSignedXml(xml);
        const validator = new XmlDSigValidator({
          keySelector: { publicCert },
          security: { hashAlgorithms: { foo: Sha1 } },
        });
        expectInvalidResult(validator.validate(signedXml), "hash algorithm");
      });
    });

    describe("transformAlgorithms", function () {
      it("should validate when transform algorithms are allowed", function () {
        const signedXml = createSignedXml(xml);
        const validator = new XmlDSigValidator({
          keySelector: { publicCert },
          security: { transformAlgorithms: SignedXml.getDefaultTransformAlgorithms() },
        });
        expectValidResult(validator.validate(signedXml));
      });

      it("should fail validation when a transform algorithm is not allowed", function () {
        const signedXml = createSignedXml(xml);
        const validator = new XmlDSigValidator({
          keySelector: { publicCert },
          security: { transformAlgorithms: { foo: EnvelopedSignature } },
        });
        expectInvalidResult(validator.validate(signedXml), "transform algorithm");
      });
    });

    describe("canonicalizationAlgorithms", function () {
      it("should validate when canonicalization algorithms are allowed", function () {
        const signedXml = createSignedXml(xml);
        const validator = new XmlDSigValidator({
          keySelector: { publicCert },
          security: {
            canonicalizationAlgorithms: SignedXml.getDefaultCanonicalizationAlgorithms(),
          },
        });
        expectValidResult(validator.validate(signedXml));
      });

      it("should fail validation when a canonicalization algorithm is not allowed", function () {
        const signedXml = createSignedXml(xml);
        const validator = new XmlDSigValidator({
          keySelector: { publicCert },
          security: { canonicalizationAlgorithms: { foo: ExclusiveCanonicalization } },
        });
        expectInvalidResult(validator.validate(signedXml), "canonicalization algorithm");
      });
    });
  });
});
