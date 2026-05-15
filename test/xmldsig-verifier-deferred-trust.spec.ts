import * as fs from "fs";
import { expect } from "chai";
import { X509Certificate } from "node:crypto";

import { XmlDSigVerifier, SignedXml, XMLDSIG_URIS, HmacSha1 } from "../src";
import type { DeferredTrustVerificationResult } from "../src/";

const { CANONICALIZATION_ALGORITHMS, HASH_ALGORITHMS, SIGNATURE_ALGORITHMS } = XMLDSIG_URIS;

const privateKey = fs.readFileSync("./test/static/client.pem", "utf-8");
const publicCert = fs.readFileSync("./test/static/client_public.pem", "utf-8");
const expiredKey = fs.readFileSync("./test/static/expired_certificate.key.pem", "utf-8");
const expiredCert = fs.readFileSync("./test/static/expired_certificate.crt.pem", "utf-8");

function createSignedXml(xml: string): string {
  const sig = new SignedXml({
    privateKey,
    canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
    signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA1,
    getKeyInfoContent: () => SignedXml.getKeyInfoContent({ publicCert }),
  });
  sig.addReference({
    xpath: "//*[local-name(.)='test']",
    digestAlgorithm: HASH_ALGORITHMS.SHA1,
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
    digestAlgorithm: HASH_ALGORITHMS.SHA1,
    transforms: [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
  });
  sig.computeSignature(xml);
  return sig.getSignedXml();
}

function expectSuccess(
  result: DeferredTrustVerificationResult,
): asserts result is Extract<DeferredTrustVerificationResult, { success: true }> {
  expect(result.success).to.be.true;
  expect(result.signatureValid).to.be.true;
  expect(result.error).to.be.undefined;
}

function expectFailure(result: DeferredTrustVerificationResult, errorFragment?: string) {
  expect(result.success).to.be.false;
  expect(result.signatureValid).to.be.false;
  expect(result.untrustedCertificate).to.be.undefined;
  expect(result.signedReferences).to.be.undefined;
  expect(result.error).to.be.a("string");
  if (errorFragment && result.error) {
    expect(result.error.toLowerCase()).to.contain(errorFragment.toLowerCase());
  }
}

describe("XmlDSigVerifier.extractAndVerify", function () {
  const xml = "<root><test>content</test></root>";

  it("returns untrustedCertificate and signedReferences on successful signature math", function () {
    const signedXml = createSignedXml(xml);
    const result = XmlDSigVerifier.extractAndVerify(signedXml, {
      keySelector: {
        getCertFromKeyInfo: (keyInfo) => SignedXml.getCertFromKeyInfo(keyInfo),
      },
    });

    expectSuccess(result);
    expect(result.untrustedCertificate).to.be.instanceOf(X509Certificate);
    expect(result.untrustedCertificate.subject).to.equal(new X509Certificate(publicCert).subject);
    expect(result.signedReferences).to.be.an("array").with.length(1);
  });

  it("succeeds for an expired certificate (math-only, no expiration check)", function () {
    const signedXml = createExpiredSignedXml(xml);
    const result = XmlDSigVerifier.extractAndVerify(signedXml, {
      keySelector: {
        getCertFromKeyInfo: (keyInfo) => SignedXml.getCertFromKeyInfo(keyInfo),
      },
    });

    expectSuccess(result);
    expect(result.untrustedCertificate.subject).to.equal(new X509Certificate(expiredCert).subject);
  });

  it("returns failure when the document has been tampered with", function () {
    const signedXml = createSignedXml(xml);
    const tampered = signedXml.replace("content", "tampered");
    const result = XmlDSigVerifier.extractAndVerify(tampered, {
      keySelector: {
        getCertFromKeyInfo: (keyInfo) => SignedXml.getCertFromKeyInfo(keyInfo),
      },
    });

    expectFailure(result, "verification failed");
  });

  it("returns failure when getCertFromKeyInfo returns null", function () {
    const signedXml = createSignedXml(xml);
    const result = XmlDSigVerifier.extractAndVerify(signedXml, {
      keySelector: { getCertFromKeyInfo: () => null },
    });

    expectFailure(result, "keyinfo");
  });

  it("returns failure when no Signature element is present", function () {
    const result = XmlDSigVerifier.extractAndVerify(xml, {
      keySelector: {
        getCertFromKeyInfo: (keyInfo) => SignedXml.getCertFromKeyInfo(keyInfo),
      },
    });

    expectFailure(result, "no signature element");
  });

  it("rejects a non-function getCertFromKeyInfo", function () {
    const signedXml = createSignedXml(xml);
    const result = XmlDSigVerifier.extractAndVerify(signedXml, {
      keySelector: { getCertFromKeyInfo: undefined as never },
    });

    expectFailure(result, "requires a valid getcertfromkeyinfo function");
  });

  it("honors throwOnError: true by throwing instead of returning a failure result", function () {
    const signedXml = createSignedXml(xml);
    const tampered = signedXml.replace("content", "tampered");

    expect(() => {
      XmlDSigVerifier.extractAndVerify(tampered, {
        keySelector: {
          getCertFromKeyInfo: (keyInfo) => SignedXml.getCertFromKeyInfo(keyInfo),
        },
        throwOnError: true,
      });
    }).to.throw("verification failed");
  });

  it("defaults throwOnError to false", function () {
    const result = XmlDSigVerifier.extractAndVerify("<root><test>content</test></root>", {
      keySelector: { getCertFromKeyInfo: () => null },
    });
    // No throw; failure surfaces as a result object.
    expectFailure(result);
  });

  it("rejects HMAC signature algorithms to prevent key confusion", function () {
    const signedXml = createSignedXml(xml);
    const result = XmlDSigVerifier.extractAndVerify(signedXml, {
      keySelector: {
        getCertFromKeyInfo: (keyInfo) => SignedXml.getCertFromKeyInfo(keyInfo),
      },
      security: { signatureAlgorithms: [HmacSha1] },
    });
    expectFailure(result, "does not support symmetric signature algorithms");
  });

  it("accepts non-symmetric custom signatureAlgorithms without complaint", function () {
    // Sanity: the HMAC guard does not over-reject. An asymmetric-only override
    // (RsaSha256, used by createSignedXml under the hood) must still succeed.
    const signedXml = createSignedXml(xml);
    const result = XmlDSigVerifier.extractAndVerify(signedXml, {
      keySelector: {
        getCertFromKeyInfo: (keyInfo) => SignedXml.getCertFromKeyInfo(keyInfo),
      },
      security: { signatureAlgorithms: [...XmlDSigVerifier.defaultAsymmetricSignatureAlgorithms] },
    });
    expectSuccess(result);
  });

  it("throws when idAttributes is provided but empty", function () {
    const signedXml = createSignedXml(xml);
    const result = XmlDSigVerifier.extractAndVerify(signedXml, {
      keySelector: {
        getCertFromKeyInfo: (keyInfo) => SignedXml.getCertFromKeyInfo(keyInfo),
      },
      idAttributes: [],
    });
    expectFailure(result, "'idAttributes' must contain at least one entry");
  });

  it("rejects truststore at the type level (regression guard)", function () {
    const signedXml = createSignedXml(xml);
    const result = XmlDSigVerifier.extractAndVerify(signedXml, {
      keySelector: {
        getCertFromKeyInfo: (keyInfo) => SignedXml.getCertFromKeyInfo(keyInfo),
      },
      // @ts-expect-error -- DeferredTrustVerifierOptions does not accept truststore
      security: { truststore: [publicCert] },
    });
    // Even at runtime the unknown field is ignored: signature math still runs
    // and the cert is returned untrusted.
    expectSuccess(result);
  });
});
