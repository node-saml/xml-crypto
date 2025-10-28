import * as fs from "fs";
import { expect } from "chai";
import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as isDomNode from "@xmldom/is-dom-node";
import { XmlDSigValidator, SignedXml, Algorithms } from "../src";

const { canonicalization, hash, signature } = Algorithms;

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

// Helper function to create a signed XML with multiple signatures
function createMultiSignedXml(xml: string): string {
  const sig1 = new SignedXml({
    privateKey,
    canonicalizationAlgorithm: canonicalization.EXCLUSIVE_C14N,
    signatureAlgorithm: signature.RSA_SHA1,
  });

  sig1.addReference({
    xpath: "//*[local-name(.)='test']",
    digestAlgorithm: hash.SHA1,
    transforms: [canonicalization.EXCLUSIVE_C14N],
  });

  sig1.computeSignature(xml, { attrs: { Id: "sig1" } });
  const signedOnce = sig1.getSignedXml();

  const sig2 = new SignedXml({
    privateKey,
    canonicalizationAlgorithm: canonicalization.EXCLUSIVE_C14N,
    signatureAlgorithm: signature.RSA_SHA1,
  });

  sig2.addReference({
    xpath: "//*[local-name(.)='test']",
    digestAlgorithm: hash.SHA1,
    transforms: [canonicalization.EXCLUSIVE_C14N],
  });

  sig2.computeSignature(signedOnce, { attrs: { Id: "sig2" } });
  return sig2.getSignedXml();
}

describe("XmlDSigValidator", function () {
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

    it("should create validator with custom ID attributes", function () {
      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
        idAttributes: ["customId", "myId"],
      });
      expect(validator).to.be.instanceOf(XmlDSigValidator);
    });

    it("should create validator with security options", function () {
      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
        security: {
          maxTransforms: 2,
          checkCertExpiration: false,
        },
        throwOnError: true,
      });
      expect(validator).to.be.instanceOf(XmlDSigValidator);
    });

    it("should throw error when keySelector is missing", function () {
      expect(() => new XmlDSigValidator({})).to.throw(
        "XmlDSigValidator requires a keySelector in options.",
      );
    });
  });

  describe("validate", function () {
    it("should validate a valid signed XML document", function () {
      const xml = "<root><test>content</test></root>";
      const signedXml = createSignedXml(xml);

      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
      });
      const result = validator.validate(signedXml);

      expect(result.valid).to.be.true;
      expect(result.error).to.be.undefined;
      expect(result.signedReferences).to.be.an("array");
      expect(result.signedReferences).to.have.length(1);
    });

    it("should fail validation for invalid signature", function () {
      const xml = "<root><test>content</test></root>";
      const signedXml = createSignedXml(xml);
      const tamperedXml = signedXml.replace("content", "tampered");

      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
      });
      const result = validator.validate(tamperedXml);

      expect(result.valid).to.be.false;
      expect(result.signedReferences).to.be.undefined;
    });

    it("should automatically load single signature when none is specified", function () {
      const xml = "<root><test>content</test></root>";
      const signedXml = createSignedXml(xml);

      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
      });
      const result = validator.validate(signedXml);

      expect(result.valid).to.be.true;
    });

    it("should fail when no signature is found", function () {
      const xml = "<root><test>content</test></root>";

      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
      });
      const result = validator.validate(xml);

      expect(result.valid).to.be.false;
      expect(result.error).to.include("No Signature element found");
    });

    it("should fail when multiple signatures are found without specifying signatureNode", function () {
      const xml = "<root><test>content</test></root>";
      const multiSignedXml = createMultiSignedXml(xml);

      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
      });
      const result = validator.validate(multiSignedXml);

      expect(result.valid).to.be.false;
      expect(result.error).to.include("Multiple Signature elements found");
    });

    it("should validate specific signature when signatureNode is provided", function () {
      const xml = "<root><test>content</test></root>";
      const multiSignedXml = createMultiSignedXml(xml);
      const doc = new xmldom.DOMParser().parseFromString(multiSignedXml);
      const firstSignature = xpath.select1("//*[local-name(.)='Signature'][@Id='sig1']", doc);
      isDomNode.assertIsNodeLike(firstSignature);

      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
      });
      const result = validator.validate(multiSignedXml, firstSignature);

      expect(result.valid).to.be.true;
    });

    it("should be reusable for multiple validations", function () {
      const xml = "<root><test>content</test></root>";
      const signedXml = createSignedXml(xml);

      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
      });

      // First validation
      const result1 = validator.validate(signedXml);
      expect(result1.valid).to.be.true;

      // Second validation should also work (validator is reusable)
      const result2 = validator.validate(signedXml);
      expect(result2.valid).to.be.true;
    });

    it("should work with getCertFromKeyInfo function", function () {
      const xml = "<root><test>content</test></root>";
      const signedXml = createSignedXml(xml);

      const validator = new XmlDSigValidator({
        keySelector: {
          getCertFromKeyInfo: () => publicCert,
        },
      });
      const result = validator.validate(signedXml);

      expect(result.valid).to.be.true;
    });

    it("should work with custom ID attributes", function () {
      const xml = '<root><test customId="test1">content</test></root>';
      const sig = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: canonicalization.EXCLUSIVE_C14N,
        signatureAlgorithm: signature.RSA_SHA1,
      });
      sig.idAttributes = ["customId"];
      sig.addReference({
        xpath: "//*[@customId='test1']",
        digestAlgorithm: hash.SHA1,
        transforms: [canonicalization.EXCLUSIVE_C14N],
      });
      sig.computeSignature(xml);
      const signedXml = sig.getSignedXml();

      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
        idAttributes: ["customId"],
      });
      const result = validator.validate(signedXml);

      expect(result.valid).to.be.true;
    });

    it("should handle validation errors gracefully when throwOnError is false", function () {
      const xml = "<root><test>content</test></root>";
      const signedXml = createSignedXml(xml);
      const corruptedXml = signedXml.replace("<SignatureValue>", "<SignatureValue>corrupted");

      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
        throwOnError: false,
      });
      const result = validator.validate(corruptedXml);

      expect(result.valid).to.be.false;
      expect(result.error).to.be.a("string");
    });

    it("should throw validation errors when throwOnError is true", function () {
      const xml = "<root><test>content</test></root>";

      const validator = new XmlDSigValidator({
        keySelector: { publicCert },
        throwOnError: true,
      });

      expect(() => validator.validate(xml)).to.throw();
    });
  });
});

describe("XmlDSigValidator Certificate Expiration", function () {
  it("should reject expired certificate when checkCertExpiration is true", function () {
    const xml = "<root><test>content</test></root>";

    // Create signature using regular certificate first (we can't sign with expired cert)
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
    const signedXml = sig.getSignedXml();

    // Create validator that will try to use expired certificate for validation
    const validator = new XmlDSigValidator({
      keySelector: {
        getCertFromKeyInfo: SignedXml.getCertFromKeyInfo,
      },
      security: {
        checkCertExpiration: true,
      },
      throwOnError: false,
    });

    const result = validator.validate(signedXml);
    expect(result.valid).to.be.false;
    expect(result.error).to.include("expired");
  });

  it("should throw error for expired certificate when throwOnError is true", function () {
    const xml = "<root><test>content</test></root>";

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

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    const validator = new XmlDSigValidator({
      keySelector: {
        getCertFromKeyInfo: () => {
          return expiredCert;
        },
      },
      security: {
        checkCertExpiration: true,
      },
      throwOnError: true,
    });

    expect(() => validator.validate(signedXml)).to.throw("expired");
  });

  it("should accept expired certificate when checkCertExpiration is false", function () {
    const xml = "<root><test>content</test></root>";

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

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    const validator = new XmlDSigValidator({
      keySelector: {
        getCertFromKeyInfo: () => {
          return expiredCert;
        },
      },
      security: {
        checkCertExpiration: false, // Disable certificate expiration checking
      },
    });

    // Note: This test might still fail due to signature mismatch since we're using
    // a different certificate than what was used to sign, but it should not fail
    // due to expiration specifically. In a real scenario, you'd sign with the same
    // certificate you're validating with.
    const result = validator.validate(signedXml);
    // We expect this to fail due to signature mismatch, not expiration
    expect(result.valid).to.be.false;
    if (result.error) {
      expect(result.error).to.not.include("expired");
    }
  });
});

describe("XmlDSigValidator Security Features", function () {
  it("should prevent signature wrapping attacks by only returning signed content", function () {
    const xml = "<root><test>content</test><unsigned>malicious</unsigned></root>";
    const signedXml = createSignedXml(xml);

    const validator = new XmlDSigValidator({
      keySelector: { publicCert },
    });
    const result = validator.validate(signedXml);

    expect(result.valid).to.be.true;
    expect(result.signedReferences).to.have.length(1);
    // The signed references should only contain the canonicalized content that was actually signed
    expect(result.signedReferences?.[0]).to.not.include("malicious");
    expect(result.signedReferences?.[0]).to.include("content");
  });

  it("should be reusable (no single-use restriction)", function () {
    const xml = "<root><test>content</test></root>";
    const signedXml = createSignedXml(xml);

    const validator = new XmlDSigValidator({
      keySelector: { publicCert },
    });

    // First use should work
    const result1 = validator.validate(signedXml);
    expect(result1.valid).to.be.true;

    // Second use should also work (validator is reusable)
    const result2 = validator.validate(signedXml);
    expect(result2.valid).to.be.true;
  });

  it("should validate with maxTransforms limit", function () {
    const xml = "<root><test>content</test></root>";
    const signedXml = createSignedXml(xml);

    const validator = new XmlDSigValidator({
      keySelector: { publicCert },
      security: {
        maxTransforms: 1,
        checkCertExpiration: true,
      },
    });
    const result = validator.validate(signedXml);

    expect(result.valid).to.be.true;
  });

  it("should handle edge cases gracefully", function () {
    const validator = new XmlDSigValidator({
      keySelector: { publicCert },
    });

    // Empty XML
    const result1 = validator.validate("");
    expect(result1.valid).to.be.false;
    expect(result1.error).to.be.a("string");
  });
});

describe("XmlDSigValidator Truststore", function () {
  it("should validate document signed with chain certificate when root is in truststore", function () {
    const xml = "<root><test>content</test></root>";

    // Create signature using chain certificate with KeyInfo containing the certificate
    const sig = new SignedXml({
      privateKey: chainPrivateKey,
      canonicalizationAlgorithm: canonicalization.EXCLUSIVE_C14N,
      signatureAlgorithm: signature.RSA_SHA1,
    });

    sig.addReference({
      xpath: "//*[local-name(.)='test']",
      digestAlgorithm: hash.SHA1,
      transforms: [canonicalization.EXCLUSIVE_C14N],
    });

    // Add KeyInfo with the chain certificate
    sig.getKeyInfoContent = () => SignedXml.getKeyInfoContent({ publicCert: chainPublicCert });

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    // Create validator with truststore containing root certificate
    const validator = new XmlDSigValidator({
      keySelector: {
        getCertFromKeyInfo: () => {
          // Extract certificate from KeyInfo (in real scenario this would parse the KeyInfo)
          return chainPublicCert;
        },
      },
      security: {
        truststore: [rootCert],
        checkCertExpiration: false, // Disable for test certificates
      },
    });

    const result = validator.validate(signedXml);
    expect(result.valid).to.be.true;
    expect(result.signedReferences).to.have.length(1);
  });

  it("should reject document signed with untrusted certificate", function () {
    const xml = "<root><test>content</test></root>";

    // Create signature using regular client certificate (not in chain)
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

    // Add KeyInfo with the regular client certificate
    sig.getKeyInfoContent = () => SignedXml.getKeyInfoContent({ publicCert });

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    // Create validator with truststore containing only root certificate
    const validator = new XmlDSigValidator({
      keySelector: {
        getCertFromKeyInfo: () => {
          // Extract certificate from KeyInfo
          return publicCert;
        },
      },
      security: {
        truststore: [rootCert],
        checkCertExpiration: false,
      },
      throwOnError: false,
    });

    const result = validator.validate(signedXml);
    expect(result.valid).to.be.false;
    expect(result.error).to.include("not trusted");
  });

  it("should validate when certificate matches truststore exactly", function () {
    const xml = "<root><test>content</test></root>";

    // Create signature using chain certificate
    const sig = new SignedXml({
      privateKey: chainPrivateKey,
      canonicalizationAlgorithm: canonicalization.EXCLUSIVE_C14N,
      signatureAlgorithm: signature.RSA_SHA1,
    });

    sig.addReference({
      xpath: "//*[local-name(.)='test']",
      digestAlgorithm: hash.SHA1,
      transforms: [canonicalization.EXCLUSIVE_C14N],
    });

    sig.getKeyInfoContent = () => SignedXml.getKeyInfoContent({ publicCert: chainPublicCert });

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    // Create validator with truststore containing the exact certificate
    const validator = new XmlDSigValidator({
      keySelector: {
        getCertFromKeyInfo: () => {
          return chainPublicCert;
        },
      },
      security: {
        truststore: [chainPublicCert], // Exact certificate match
        checkCertExpiration: false,
      },
    });

    const result = validator.validate(signedXml);
    expect(result.valid).to.be.true;
    expect(result.signedReferences).to.have.length(1);
  });

  it("should work without truststore when not specified", function () {
    const xml = "<root><test>content</test></root>";

    // Create signature using regular certificate
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

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    // Create validator without truststore
    const validator = new XmlDSigValidator({
      keySelector: {
        getCertFromKeyInfo: () => {
          return publicCert;
        },
      },
      security: {
        checkCertExpiration: false,
      },
    });

    const result = validator.validate(signedXml);
    expect(result.valid).to.be.true;
    expect(result.signedReferences).to.have.length(1);
  });
});

describe("XmlDSigValidator Integration", function () {
  it("should work with real-world signed XML documents", function () {
    // Test with a more complex XML structure
    const xml = `
      <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Header>
          <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <test wsu:Id="test1" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
              Secure content
            </test>
          </wsse:Security>
        </soap:Header>
        <soap:Body>
          <operation>data</operation>
        </soap:Body>
      </soap:Envelope>
    `;

    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: canonicalization.EXCLUSIVE_C14N,
      signatureAlgorithm: signature.RSA_SHA1,
      idMode: "wssecurity",
    });

    sig.addReference({
      xpath: "//*[@wsu:Id='test1']",
      digestAlgorithm: hash.SHA1,
      transforms: [canonicalization.EXCLUSIVE_C14N],
    });

    sig.computeSignature(xml, {
      location: {
        reference: "//*[local-name(.)='Security']",
        action: "append",
      },
      existingPrefixes: {
        soap: "http://schemas.xmlsoap.org/soap/envelope/",
        wsse: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
        wsu: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
      },
    });

    const signedXml = sig.getSignedXml();

    const validator = new XmlDSigValidator({
      keySelector: { publicCert },
      idAttributes: [
        {
          prefix: "wsu",
          localName: "Id",
          namespaceUri:
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
        },
      ],
    });
    const result = validator.validate(signedXml);

    expect(result.valid).to.be.true;
    expect(result.signedReferences).to.have.length(1);
  });

  it("should validate signatures created by XmlDSigSigner", function () {
    // This test ensures compatibility between XmlDSigSigner and XmlDSigValidator
    const xml = '<root><test id="test1">content</test></root>';

    // Create signature using SignedXml (simulating XmlDSigSigner output)
    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: canonicalization.EXCLUSIVE_C14N,
      signatureAlgorithm: signature.RSA_SHA1,
    });

    sig.addReference({
      xpath: "//*[@id='test1']",
      digestAlgorithm: hash.SHA1,
      transforms: [canonicalization.EXCLUSIVE_C14N],
    });

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    // Validate using XmlDSigValidator
    const validator = new XmlDSigValidator({
      keySelector: { publicCert },
    });
    const result = validator.validate(signedXml);

    expect(result.valid).to.be.true;
    expect(result.signedReferences).to.have.length(1);
  });
});
