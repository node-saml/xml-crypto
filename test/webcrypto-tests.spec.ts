import { SignedXml } from "../src/signed-xml";
import { WebCryptoSha1, WebCryptoSha256, WebCryptoSha512 } from "../src/hash-algorithms-webcrypto";
import {
  WebCryptoRsaSha1,
  WebCryptoRsaSha256,
  WebCryptoRsaSha512,
  WebCryptoHmacSha1,
} from "../src/signature-algorithms-webcrypto";
import { importRsaPrivateKey, importRsaPublicKey } from "../src/webcrypto-utils";
import { expect } from "chai";
import { readFileSync } from "fs";

describe("WebCrypto Hash Algorithms", function () {
  it("WebCryptoSha1 should compute hash correctly", async function () {
    const hash = new WebCryptoSha1();
    const xml = "<test>data</test>";
    const digest = await hash.getHash(xml);

    // Verify it returns a base64 string
    expect(digest).to.be.a("string");
    expect(digest.length).to.be.greaterThan(0);
    expect(() => Buffer.from(digest, "base64")).to.not.throw();

    // Verify algorithm name
    expect(hash.getAlgorithmName()).to.equal("http://www.w3.org/2000/09/xmldsig#sha1");
  });

  it("WebCryptoSha256 should compute hash correctly", async function () {
    const hash = new WebCryptoSha256();
    const xml = "<test>data</test>";
    const digest = await hash.getHash(xml);

    expect(digest).to.be.a("string");
    expect(digest.length).to.be.greaterThan(0);
    expect(() => Buffer.from(digest, "base64")).to.not.throw();
    expect(hash.getAlgorithmName()).to.equal("http://www.w3.org/2001/04/xmlenc#sha256");
  });

  it("WebCryptoSha512 should compute hash correctly", async function () {
    const hash = new WebCryptoSha512();
    const xml = "<test>data</test>";
    const digest = await hash.getHash(xml);

    expect(digest).to.be.a("string");
    expect(digest.length).to.be.greaterThan(0);
    expect(() => Buffer.from(digest, "base64")).to.not.throw();
    expect(hash.getAlgorithmName()).to.equal("http://www.w3.org/2001/04/xmlenc#sha512");
  });

  it("should produce consistent hashes for same input", async function () {
    const hash = new WebCryptoSha256();
    const xml = "<test>consistent data</test>";
    const digest1 = await hash.getHash(xml);
    const digest2 = await hash.getHash(xml);

    expect(digest1).to.equal(digest2);
  });

  it("should produce different hashes for different inputs", async function () {
    const hash = new WebCryptoSha256();
    const xml1 = "<test>data1</test>";
    const xml2 = "<test>data2</test>";
    const digest1 = await hash.getHash(xml1);
    const digest2 = await hash.getHash(xml2);

    expect(digest1).to.not.equal(digest2);
  });
});

describe("WebCrypto Key Import Utilities", function () {
  it("should import RSA private key from PEM", async function () {
    const pem = readFileSync("./test/static/client.pem", "utf8");
    const key = await importRsaPrivateKey(pem, "SHA-256");

    expect(key).to.be.instanceOf(CryptoKey);
    expect(key.type).to.equal("private");
    expect(key.algorithm.name).to.equal("RSASSA-PKCS1-v1_5");
  });

  it("should import RSA public key from PEM", async function () {
    const pem = readFileSync("./test/static/client_public.pem", "utf8");

    // Extract public key using Node.js crypto first
    const crypto = await import("crypto");
    const publicKeyObj = crypto.createPublicKey(pem);
    const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

    const key = await importRsaPublicKey(spkiPem, "SHA-256");

    expect(key).to.be.instanceOf(CryptoKey);
    expect(key.type).to.equal("public");
    expect(key.algorithm.name).to.equal("RSASSA-PKCS1-v1_5");
  });
});

describe("WebCrypto RSA Signature Algorithms", function () {
  let privateKey: string;
  let publicKey: string;

  before(function () {
    privateKey = readFileSync("./test/static/client.pem", "utf8");
    publicKey = readFileSync("./test/static/client_public.pem", "utf8");
  });

  describe("WebCryptoRsaSha256", function () {
    it("should sign and verify data correctly", async function () {
      const algo = new WebCryptoRsaSha256();
      const data = "test data to sign";

      const signature = await algo.getSignature(data, privateKey);
      expect(signature).to.be.a("string");
      expect(signature.length).to.be.greaterThan(0);

      // Extract public key to SPKI format for WebCrypto
      const crypto = await import("crypto");
      const publicKeyObj = crypto.createPublicKey(publicKey);
      const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

      const isValid = await algo.verifySignature(data, spkiPem, signature);
      expect(isValid).to.be.true;
    });

    it("should fail verification with wrong data", async function () {
      const algo = new WebCryptoRsaSha256();
      const data = "test data to sign";

      const signature = await algo.getSignature(data, privateKey);

      const crypto = await import("crypto");
      const publicKeyObj = crypto.createPublicKey(publicKey);
      const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

      const isValid = await algo.verifySignature("wrong data", spkiPem, signature);
      expect(isValid).to.be.false;
    });

    it("should have correct algorithm name", function () {
      const algo = new WebCryptoRsaSha256();
      expect(algo.getAlgorithmName()).to.equal("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    });
  });

  describe("WebCryptoRsaSha1", function () {
    it("should sign and verify data correctly", async function () {
      const algo = new WebCryptoRsaSha1();
      const data = "test data to sign";

      const signature = await algo.getSignature(data, privateKey);
      expect(signature).to.be.a("string");

      const crypto = await import("crypto");
      const publicKeyObj = crypto.createPublicKey(publicKey);
      const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

      const isValid = await algo.verifySignature(data, spkiPem, signature);
      expect(isValid).to.be.true;
    });

    it("should have correct algorithm name", function () {
      const algo = new WebCryptoRsaSha1();
      expect(algo.getAlgorithmName()).to.equal("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
    });
  });

  describe("WebCryptoRsaSha512", function () {
    it("should sign and verify data correctly", async function () {
      const algo = new WebCryptoRsaSha512();
      const data = "test data to sign";

      const signature = await algo.getSignature(data, privateKey);
      expect(signature).to.be.a("string");

      const crypto = await import("crypto");
      const publicKeyObj = crypto.createPublicKey(publicKey);
      const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

      const isValid = await algo.verifySignature(data, spkiPem, signature);
      expect(isValid).to.be.true;
    });

    it("should have correct algorithm name", function () {
      const algo = new WebCryptoRsaSha512();
      expect(algo.getAlgorithmName()).to.equal("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
    });
  });
});

describe("WebCrypto HMAC Signature Algorithm", function () {
  describe("WebCryptoHmacSha1", function () {
    it("should sign and verify data correctly", async function () {
      const algo = new WebCryptoHmacSha1();
      const data = "test data to sign";
      const key = "my-secret-key";

      const signature = await algo.getSignature(data, key);
      expect(signature).to.be.a("string");
      expect(signature.length).to.be.greaterThan(0);

      const isValid = await algo.verifySignature(data, key, signature);
      expect(isValid).to.be.true;
    });

    it("should fail verification with wrong key", async function () {
      const algo = new WebCryptoHmacSha1();
      const data = "test data to sign";
      const key = "my-secret-key";

      const signature = await algo.getSignature(data, key);

      const isValid = await algo.verifySignature(data, "wrong-key", signature);
      expect(isValid).to.be.false;
    });

    it("should have correct algorithm name", function () {
      const algo = new WebCryptoHmacSha1();
      expect(algo.getAlgorithmName()).to.equal("http://www.w3.org/2000/09/xmldsig#hmac-sha1");
    });
  });
});

describe("WebCrypto XML Signing and Verification", function () {
  let privateKey: string;
  let publicKey: string;

  before(function () {
    privateKey = readFileSync("./test/static/client.pem", "utf8");
    publicKey = readFileSync("./test/static/client_public.pem", "utf8");
  });

  it("should sign and verify XML with WebCrypto RSA-SHA256", async function () {
    const xml = "<library><book><name>Harry Potter</name></book></library>";

    // Sign
    const sig = new SignedXml();
    sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sig.privateKey = privateKey;

    sig.addReference({
      xpath: "//*[local-name(.)='book']",
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    // Register WebCrypto algorithms
    sig.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
    sig.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] =
      WebCryptoRsaSha256;

    await sig.computeSignatureAsync(xml);
    const signedXml = sig.getSignedXml();

    expect(signedXml).to.include("<Signature");
    expect(signedXml).to.include("<SignatureValue>");

    // Verify
    const verifier = new SignedXml();

    // Convert certificate to SPKI format for WebCrypto
    const crypto = await import("crypto");
    const publicKeyObj = crypto.createPublicKey(publicKey);
    const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

    verifier.publicCert = spkiPem;

    verifier.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
    verifier.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] =
      WebCryptoRsaSha256;

    const isValid = await verifier.checkSignatureAsync(signedXml);
    expect(isValid).to.be.true;
  });

  it("should sign and verify XML with WebCrypto RSA-SHA1", async function () {
    const xml = "<root><data>test content</data></root>";

    // Sign
    const sig = new SignedXml();
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sig.privateKey = privateKey;

    sig.addReference({
      xpath: "//*[local-name(.)='data']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    sig.HashAlgorithms["http://www.w3.org/2000/09/xmldsig#sha1"] = WebCryptoSha1;
    sig.SignatureAlgorithms["http://www.w3.org/2000/09/xmldsig#rsa-sha1"] = WebCryptoRsaSha1;

    await sig.computeSignatureAsync(xml);
    const signedXml = sig.getSignedXml();

    // Verify
    const verifier = new SignedXml();

    const crypto = await import("crypto");
    const publicKeyObj = crypto.createPublicKey(publicKey);
    const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

    verifier.publicCert = spkiPem;

    verifier.HashAlgorithms["http://www.w3.org/2000/09/xmldsig#sha1"] = WebCryptoSha1;
    verifier.SignatureAlgorithms["http://www.w3.org/2000/09/xmldsig#rsa-sha1"] = WebCryptoRsaSha1;

    const isValid = await verifier.checkSignatureAsync(signedXml);
    expect(isValid).to.be.true;
  });

  it("should detect invalid signatures", async function () {
    const xml = "<root><data>test content</data></root>";

    // Sign
    const sig = new SignedXml();
    sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sig.privateKey = privateKey;

    sig.addReference({
      xpath: "//*[local-name(.)='data']",
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    sig.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
    sig.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] =
      WebCryptoRsaSha256;

    await sig.computeSignatureAsync(xml);
    let signedXml = sig.getSignedXml();

    // Tamper with the signed data
    signedXml = signedXml.replace("test content", "tampered content");

    // Verify should fail
    const verifier = new SignedXml();

    const crypto = await import("crypto");
    const publicKeyObj = crypto.createPublicKey(publicKey);
    const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

    verifier.publicCert = spkiPem;

    verifier.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
    verifier.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] =
      WebCryptoRsaSha256;

    try {
      await verifier.checkSignatureAsync(signedXml);
      expect.fail("Should have thrown an error for invalid signature");
    } catch (error) {
      expect((error as Error).message).to.include("Could not validate all references");
    }
  });

  it("should throw error when using async algorithms with sync methods", function () {
    const xml = "<root><data>test</data></root>";

    const sig = new SignedXml();
    sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sig.privateKey = privateKey;

    sig.addReference({
      xpath: "//*[local-name(.)='data']",
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    // Register WebCrypto algorithms
    sig.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
    sig.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] =
      WebCryptoRsaSha256;

    // Should throw when using sync method with async algorithm
    expect(() => sig.computeSignature(xml)).to.throw(
      "Async signature algorithms cannot be used with sync methods",
    );
  });

  it("should throw error when verifying with async algorithms using sync methods", async function () {
    const xml = "<root><data>test</data></root>";

    // First, create a signed XML using async methods
    const signer = new SignedXml();
    signer.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    signer.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    signer.privateKey = privateKey;

    signer.addReference({
      xpath: "//*[local-name(.)='data']",
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    signer.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
    signer.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] =
      WebCryptoRsaSha256;

    await signer.computeSignatureAsync(xml);
    const signedXml = signer.getSignedXml();

    // Now try to verify using sync method - should throw
    const verifier = new SignedXml();

    const crypto = await import("crypto");
    const publicKeyObj = crypto.createPublicKey(publicKey);
    const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

    verifier.publicCert = spkiPem;
    verifier.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
    verifier.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] =
      WebCryptoRsaSha256;

    // Should throw when using sync method with async algorithm for verification
    expect(() => verifier.checkSignature(signedXml)).to.throw(
      "Async algorithms cannot be used with synchronous methods",
    );
  });

  it("should work with multiple references", async function () {
    const xml = "<root><item id='1'>First</item><item id='2'>Second</item></root>";

    const sig = new SignedXml();
    sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sig.privateKey = privateKey;

    // Add multiple references
    sig.addReference({
      xpath: "//*[local-name(.)='item'][@id='1']",
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    sig.addReference({
      xpath: "//*[local-name(.)='item'][@id='2']",
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    sig.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
    sig.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] =
      WebCryptoRsaSha256;

    await sig.computeSignatureAsync(xml);
    const signedXml = sig.getSignedXml();

    // Verify
    const verifier = new SignedXml();

    const crypto = await import("crypto");
    const publicKeyObj = crypto.createPublicKey(publicKey);
    const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

    verifier.publicCert = spkiPem;

    verifier.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
    verifier.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] =
      WebCryptoRsaSha256;

    const isValid = await verifier.checkSignatureAsync(signedXml);
    expect(isValid).to.be.true;
  });
});

describe("WebCrypto HMAC XML Signing", function () {
  it("should sign and verify XML with HMAC-SHA1", async function () {
    const xml = "<root><data>HMAC test</data></root>";
    const hmacKey = "my-secret-hmac-key";

    // Sign
    const sig = new SignedXml();
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
    sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sig.privateKey = hmacKey;

    sig.addReference({
      xpath: "//*[local-name(.)='data']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    sig.HashAlgorithms["http://www.w3.org/2000/09/xmldsig#sha1"] = WebCryptoSha1;
    sig.SignatureAlgorithms["http://www.w3.org/2000/09/xmldsig#hmac-sha1"] = WebCryptoHmacSha1;

    await sig.computeSignatureAsync(xml);
    const signedXml = sig.getSignedXml();

    // Verify
    const verifier = new SignedXml();
    verifier.publicCert = hmacKey;

    verifier.HashAlgorithms["http://www.w3.org/2000/09/xmldsig#sha1"] = WebCryptoSha1;
    verifier.SignatureAlgorithms["http://www.w3.org/2000/09/xmldsig#hmac-sha1"] = WebCryptoHmacSha1;

    const isValid = await verifier.checkSignatureAsync(signedXml);
    expect(isValid).to.be.true;
  });
});

describe("WebCrypto Callback-Style API", function () {
  let privateKey: string;
  let publicKey: string;

  before(function () {
    privateKey = readFileSync("./test/static/client.pem", "utf8");
    publicKey = readFileSync("./test/static/client_public.pem", "utf8");
  });

  it("should support callback-style getSignature for RSA-SHA1", function (done) {
    const signer = new WebCryptoRsaSha1();
    const data = "test data";

    signer.getSignature(data, privateKey, (err, signature) => {
      if (err) {
        return done(err);
      }
      expect(signature).to.be.a("string");
      if (signature) {
        expect(signature.length).to.be.greaterThan(0);
      }
      done();
    });
  });

  it("should support callback-style verifySignature for RSA-SHA256", function (done) {
    const signer = new WebCryptoRsaSha256();
    const data = "test data";

    // First sign
    signer.getSignature(data, privateKey, async (err, signature) => {
      if (err || !signature) {
        return done(err || new Error("No signature"));
      }

      // Then verify with callback
      const crypto = await import("crypto");
      const publicKeyObj = crypto.createPublicKey(publicKey);
      const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

      signer.verifySignature(data, spkiPem, signature, (verifyErr, isValid) => {
        if (verifyErr) {
          return done(verifyErr);
        }
        expect(isValid).to.be.true;
        done();
      });
    });
  });

  it("should support callback-style for HMAC-SHA1", function (done) {
    const signer = new WebCryptoHmacSha1();
    const data = "test data";
    const key = "my-hmac-key";

    signer.getSignature(data, key, (err, signature) => {
      if (err || !signature) {
        return done(err || new Error("No signature"));
      }

      signer.verifySignature(data, key, signature, (verifyErr, isValid) => {
        if (verifyErr) {
          return done(verifyErr);
        }
        expect(isValid).to.be.true;
        done();
      });
    });
  });

  it("should handle errors in callback-style API", function (done) {
    const signer = new WebCryptoRsaSha1();
    const data = "test data";
    const invalidKey = "not a valid key";

    signer.getSignature(data, invalidKey, (err) => {
      expect(err).to.exist;
      expect(err).to.be.instanceOf(Error);
      done();
    });
  });

  it("should support promise-style alongside callback-style", async function () {
    const signer = new WebCryptoRsaSha256();
    const data = "test data";

    // Promise-style should still work
    const signature = await signer.getSignature(data, privateKey);
    expect(signature).to.be.a("string");
    expect(signature.length).to.be.greaterThan(0);
  });
});

describe("WebCrypto Key Type Support", function () {
  let privateKeyString: string;
  let privateKeyBuffer: Buffer;
  let publicKeyString: string;
  let publicKeyBuffer: Buffer;

  before(function () {
    privateKeyString = readFileSync("./test/static/client.pem", "utf8");
    privateKeyBuffer = readFileSync("./test/static/client.pem");
    publicKeyString = readFileSync("./test/static/client_public.pem", "utf8");
    publicKeyBuffer = readFileSync("./test/static/client_public.pem");
  });

  it("should accept Buffer as private key for signing", async function () {
    const signer = new WebCryptoRsaSha256();
    const data = "test data with buffer key";

    const signature = await signer.getSignature(data, privateKeyBuffer);
    expect(signature).to.be.a("string");
    expect(signature.length).to.be.greaterThan(0);
  });

  it("should accept Buffer as public key for verification", async function () {
    const signer = new WebCryptoRsaSha256();
    const data = "test data with buffer key";

    // Sign with string key
    const signature = await signer.getSignature(data, privateKeyString);

    // Verify with buffer key
    const crypto = await import("crypto");
    const publicKeyObj = crypto.createPublicKey(publicKeyBuffer);
    const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

    const isValid = await signer.verifySignature(data, Buffer.from(spkiPem), signature);
    expect(isValid).to.be.true;
  });

  it("should accept KeyObject as private key for signing", async function () {
    const crypto = await import("crypto");
    const signer = new WebCryptoRsaSha256();
    const data = "test data with KeyObject";

    const privateKeyObj = crypto.createPrivateKey(privateKeyString);
    const signature = await signer.getSignature(data, privateKeyObj);
    expect(signature).to.be.a("string");
    expect(signature.length).to.be.greaterThan(0);
  });

  it("should accept KeyObject as public key for verification", async function () {
    const crypto = await import("crypto");
    const signer = new WebCryptoRsaSha256();
    const data = "test data with KeyObject";

    // Sign with string key
    const signature = await signer.getSignature(data, privateKeyString);

    // Verify with KeyObject
    const publicKeyObj = crypto.createPublicKey(publicKeyString);

    const isValid = await signer.verifySignature(data, publicKeyObj, signature);
    expect(isValid).to.be.true;
  });

  it("should accept secret KeyObject for HMAC signing", async function () {
    const crypto = await import("crypto");
    const signer = new WebCryptoHmacSha1();
    const data = "test data with secret KeyObject";

    // Create a secret KeyObject
    const secretKey = crypto.createSecretKey(Uint8Array.from(Buffer.from("my-hmac-secret-key")));
    const signature = await signer.getSignature(data, secretKey);
    expect(signature).to.be.a("string");
    expect(signature.length).to.be.greaterThan(0);

    // Verify with same secret KeyObject
    const isValid = await signer.verifySignature(data, secretKey, signature);
    expect(isValid).to.be.true;
  });

  it("should accept Uint8Array as key", async function () {
    const signer = new WebCryptoRsaSha256();
    const data = "test data with Uint8Array";

    const privateKeyUint8 = new Uint8Array(privateKeyBuffer);
    const signature = await signer.getSignature(data, privateKeyUint8);
    expect(signature).to.be.a("string");
    expect(signature.length).to.be.greaterThan(0);
  });

  it("should work with Buffer keys in callback-style API", function (done) {
    const signer = new WebCryptoRsaSha256();
    const data = "test data with buffer in callback";

    signer.getSignature(data, privateKeyBuffer, (err, signature) => {
      if (err) {
        return done(err);
      }
      expect(signature).to.be.a("string");
      if (signature) {
        expect(signature.length).to.be.greaterThan(0);
      }
      done();
    });
  });
});
