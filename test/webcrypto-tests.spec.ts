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
import * as xmldom from "@xmldom/xmldom";

describe("WebCrypto Hash Algorithms", function () {
  it("WebCryptoSha1 should compute hash correctly", function (done) {
    const hash = new WebCryptoSha1();
    const xml = "<test>data</test>";
    hash.getHash(xml, (err, digest) => {
      if (err) return done(err);

      // Verify it returns a base64 string
      expect(digest).to.be.a("string");
      if (digest) {
        expect(digest.length).to.be.greaterThan(0);
        expect(() => Buffer.from(digest, "base64")).to.not.throw();
      }

      // Verify algorithm name
      expect(hash.getAlgorithmName()).to.equal("http://www.w3.org/2000/09/xmldsig#sha1");
      done();
    });
  });

  it("WebCryptoSha256 should compute hash correctly", function (done) {
    const hash = new WebCryptoSha256();
    const xml = "<test>data</test>";
    hash.getHash(xml, (err, digest) => {
      if (err) return done(err);

      expect(digest).to.be.a("string");
      if (digest) {
        expect(digest.length).to.be.greaterThan(0);
        expect(() => Buffer.from(digest, "base64")).to.not.throw();
      }
      expect(hash.getAlgorithmName()).to.equal("http://www.w3.org/2001/04/xmlenc#sha256");
      done();
    });
  });

  it("WebCryptoSha512 should compute hash correctly", function (done) {
    const hash = new WebCryptoSha512();
    const xml = "<test>data</test>";
    hash.getHash(xml, (err, digest) => {
      if (err) return done(err);

      expect(digest).to.be.a("string");
      if (digest) {
        expect(digest.length).to.be.greaterThan(0);
        expect(() => Buffer.from(digest, "base64")).to.not.throw();
      }
      expect(hash.getAlgorithmName()).to.equal("http://www.w3.org/2001/04/xmlenc#sha512");
      done();
    });
  });

  it("should produce consistent hashes for same input", function (done) {
    const hash = new WebCryptoSha256();
    const xml = "<test>consistent data</test>";
    hash.getHash(xml, (err1, digest1) => {
      if (err1) return done(err1);

      hash.getHash(xml, (err2, digest2) => {
        if (err2) return done(err2);

        expect(digest1).to.equal(digest2);
        done();
      });
    });
  });

  it("should produce different hashes for different inputs", function (done) {
    const hash = new WebCryptoSha256();
    const xml1 = "<test>data1</test>";
    const xml2 = "<test>data2</test>";
    hash.getHash(xml1, (err1, digest1) => {
      if (err1) return done(err1);

      hash.getHash(xml2, (err2, digest2) => {
        if (err2) return done(err2);

        expect(digest1).to.not.equal(digest2);
        done();
      });
    });
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
    it("should sign and verify data correctly", function (done) {
      const algo = new WebCryptoRsaSha256();
      const data = "test data to sign";

      algo.getSignature(data, privateKey, async (err, signature) => {
        if (err) return done(err);

        expect(signature).to.be.a("string");
        if (signature) {
          expect(signature.length).to.be.greaterThan(0);
        }

        // Extract public key to SPKI format for WebCrypto
        const crypto = await import("crypto");
        const publicKeyObj = crypto.createPublicKey(publicKey);
        const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

        algo.verifySignature(data, spkiPem, signature!, (verifyErr, isValid) => {
          if (verifyErr) return done(verifyErr);

          expect(isValid).to.be.true;
          done();
        });
      });
    });

    it("should fail verification with wrong data", function (done) {
      const algo = new WebCryptoRsaSha256();
      const data = "test data to sign";

      algo.getSignature(data, privateKey, async (err, signature) => {
        if (err) return done(err);

        const crypto = await import("crypto");
        const publicKeyObj = crypto.createPublicKey(publicKey);
        const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

        algo.verifySignature("wrong data", spkiPem, signature!, (verifyErr, isValid) => {
          if (verifyErr) return done(verifyErr);

          expect(isValid).to.be.false;
          done();
        });
      });
    });

    it("should have correct algorithm name", function () {
      const algo = new WebCryptoRsaSha256();
      expect(algo.getAlgorithmName()).to.equal("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    });
  });

  describe("WebCryptoRsaSha1", function () {
    it("should sign and verify data correctly", function (done) {
      const algo = new WebCryptoRsaSha1();
      const data = "test data to sign";

      algo.getSignature(data, privateKey, async (err, signature) => {
        if (err) return done(err);

        expect(signature).to.be.a("string");

        const crypto = await import("crypto");
        const publicKeyObj = crypto.createPublicKey(publicKey);
        const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

        algo.verifySignature(data, spkiPem, signature!, (verifyErr, isValid) => {
          if (verifyErr) return done(verifyErr);

          expect(isValid).to.be.true;
          done();
        });
      });
    });

    it("should have correct algorithm name", function () {
      const algo = new WebCryptoRsaSha1();
      expect(algo.getAlgorithmName()).to.equal("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
    });
  });

  describe("WebCryptoRsaSha512", function () {
    it("should sign and verify data correctly", function (done) {
      const algo = new WebCryptoRsaSha512();
      const data = "test data to sign";

      algo.getSignature(data, privateKey, async (err, signature) => {
        if (err) return done(err);

        expect(signature).to.be.a("string");

        const crypto = await import("crypto");
        const publicKeyObj = crypto.createPublicKey(publicKey);
        const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

        algo.verifySignature(data, spkiPem, signature!, (verifyErr, isValid) => {
          if (verifyErr) return done(verifyErr);

          expect(isValid).to.be.true;
          done();
        });
      });
    });

    it("should have correct algorithm name", function () {
      const algo = new WebCryptoRsaSha512();
      expect(algo.getAlgorithmName()).to.equal("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
    });
  });
});

describe("WebCrypto HMAC Signature Algorithm", function () {
  describe("WebCryptoHmacSha1", function () {
    it("should sign and verify data correctly", function (done) {
      const algo = new WebCryptoHmacSha1();
      const data = "test data to sign";
      const key = "my-secret-key";

      algo.getSignature(data, key, (err, signature) => {
        if (err) return done(err);

        expect(signature).to.be.a("string");
        if (signature) {
          expect(signature.length).to.be.greaterThan(0);
        }

        algo.verifySignature(data, key, signature!, (verifyErr, isValid) => {
          if (verifyErr) return done(verifyErr);

          expect(isValid).to.be.true;
          done();
        });
      });
    });

    it("should fail verification with wrong key", function (done) {
      const algo = new WebCryptoHmacSha1();
      const data = "test data to sign";
      const key = "my-secret-key";

      algo.getSignature(data, key, (err, signature) => {
        if (err) return done(err);

        algo.verifySignature(data, "wrong-key", signature!, (verifyErr, isValid) => {
          if (verifyErr) return done(verifyErr);

          expect(isValid).to.be.false;
          done();
        });
      });
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

  it("should sign and verify XML with WebCrypto RSA-SHA256", function (done) {
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

    sig.computeSignature(xml, (err) => {
      if (err) {
        return done(err);
      }

      const signedXml = sig.getSignedXml();

      expect(signedXml).to.include("<Signature");
      expect(signedXml).to.include("<SignatureValue>");

      // Verify
      const verifier = new SignedXml();

      // Convert certificate to SPKI format for WebCrypto
      import("crypto")
        .then((crypto) => {
          const publicKeyObj = crypto.createPublicKey(publicKey);
          const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

          verifier.publicCert = spkiPem;

          verifier.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
          verifier.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] =
            WebCryptoRsaSha256;

          // Load signature from the signed XML
          const doc = new xmldom.DOMParser().parseFromString(signedXml);
          const signature = verifier.findSignatures(doc)[0];
          verifier.loadSignature(signature);

          verifier.checkSignature(signedXml, (error, isValid) => {
            if (error) {
              return done(error);
            }
            expect(isValid).to.be.true;
            done();
          });
        })
        .catch(done);
    });
  });

  it("should sign and verify XML with WebCrypto RSA-SHA1", function (done) {
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

    sig.computeSignature(xml, (err) => {
      if (err) {
        return done(err);
      }

      const signedXml = sig.getSignedXml();

      // Verify
      const verifier = new SignedXml();

      import("crypto")
        .then((crypto) => {
          const publicKeyObj = crypto.createPublicKey(publicKey);
          const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

          verifier.publicCert = spkiPem;

          verifier.HashAlgorithms["http://www.w3.org/2000/09/xmldsig#sha1"] = WebCryptoSha1;
          verifier.SignatureAlgorithms["http://www.w3.org/2000/09/xmldsig#rsa-sha1"] =
            WebCryptoRsaSha1;

          // Load signature from the signed XML
          const doc = new xmldom.DOMParser().parseFromString(signedXml);
          const signature = verifier.findSignatures(doc)[0];
          verifier.loadSignature(signature);

          verifier.checkSignature(signedXml, (error, isValid) => {
            if (error) {
              return done(error);
            }
            expect(isValid).to.be.true;
            done();
          });
        })
        .catch(done);
    });
  });

  it("should detect invalid signatures", function (done) {
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

    sig.computeSignature(xml, (err) => {
      if (err) {
        return done(err);
      }

      let signedXml = sig.getSignedXml();

      // Tamper with the signed data
      signedXml = signedXml.replace("test content", "tampered content");

      // Verify should fail
      const verifier = new SignedXml();

      import("crypto")
        .then((crypto) => {
          const publicKeyObj = crypto.createPublicKey(publicKey);
          const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

          verifier.publicCert = spkiPem;

          verifier.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
          verifier.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] =
            WebCryptoRsaSha256;

          // Load signature from the signed XML
          const doc = new xmldom.DOMParser().parseFromString(signedXml);
          const signature = verifier.findSignatures(doc)[0];
          verifier.loadSignature(signature);

          verifier.checkSignature(signedXml, (error, isValid) => {
            expect(error).to.exist;
            expect(error?.message).to.include("invalid signature");
            expect(isValid).to.be.false;
            done();
          });
        })
        .catch(done);
    });
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
    // Hash computation happens first, so we get hash algorithm error
    expect(() => sig.computeSignature(xml)).to.throw(
      "WebCrypto hash algorithms are async and require a callback",
    );
  });

  it("should throw error when verifying with async algorithms using sync methods", function (done) {
    const xml = "<root><data>test</data></root>";

    // First, create a signed XML using callbacks
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

    signer.computeSignature(xml, (err) => {
      if (err) {
        return done(err);
      }

      const signedXml = signer.getSignedXml();

      // Now try to verify using sync method - should throw
      const verifier = new SignedXml();

      import("crypto")
        .then((crypto) => {
          const publicKeyObj = crypto.createPublicKey(publicKey);
          const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

          verifier.publicCert = spkiPem;
          verifier.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
          verifier.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] =
            WebCryptoRsaSha256;

          // Load signature first
          const doc = new xmldom.DOMParser().parseFromString(signedXml);
          const signature = verifier.findSignatures(doc)[0];
          verifier.loadSignature(signature);

          // Should throw when using sync method with async algorithm for verification
          // Hash validation happens first, so we get hash algorithm error
          expect(() => verifier.checkSignature(signedXml)).to.throw(
            "WebCrypto hash algorithms are async and require a callback",
          );
          done();
        })
        .catch(done);
    });
  });

  it("should work with multiple references", function (done) {
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

    sig.computeSignature(xml, (err) => {
      if (err) {
        return done(err);
      }

      const signedXml = sig.getSignedXml();

      // Verify
      const verifier = new SignedXml();

      import("crypto")
        .then((crypto) => {
          const publicKeyObj = crypto.createPublicKey(publicKey);
          const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

          verifier.publicCert = spkiPem;

          verifier.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
          verifier.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] =
            WebCryptoRsaSha256;

          // Load signature from the signed XML
          const doc = new xmldom.DOMParser().parseFromString(signedXml);
          const signature = verifier.findSignatures(doc)[0];
          verifier.loadSignature(signature);

          verifier.checkSignature(signedXml, (error, isValid) => {
            if (error) {
              return done(error);
            }
            expect(isValid).to.be.true;
            done();
          });
        })
        .catch(done);
    });
  });
});

describe("WebCrypto HMAC XML Signing", function () {
  it("should sign and verify XML with HMAC-SHA1", function (done) {
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

    sig.computeSignature(xml, (err) => {
      if (err) {
        return done(err);
      }

      const signedXml = sig.getSignedXml();

      // Verify
      const verifier = new SignedXml();
      verifier.publicCert = hmacKey;

      verifier.HashAlgorithms["http://www.w3.org/2000/09/xmldsig#sha1"] = WebCryptoSha1;
      verifier.SignatureAlgorithms["http://www.w3.org/2000/09/xmldsig#hmac-sha1"] =
        WebCryptoHmacSha1;

      // Load signature from the signed XML
      const doc = new xmldom.DOMParser().parseFromString(signedXml);
      const signature = verifier.findSignatures(doc)[0];
      verifier.loadSignature(signature);

      verifier.checkSignature(signedXml, (error, isValid) => {
        if (error) {
          return done(error);
        }
        expect(isValid).to.be.true;
        done();
      });
    });
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

  it("should accept Buffer as private key for signing", function (done) {
    const signer = new WebCryptoRsaSha256();
    const data = "test data with buffer key";

    signer.getSignature(data, privateKeyBuffer, (err, signature) => {
      if (err) return done(err);

      expect(signature).to.be.a("string");
      if (signature) {
        expect(signature.length).to.be.greaterThan(0);
      }
      done();
    });
  });

  it("should accept Buffer as public key for verification", function (done) {
    const signer = new WebCryptoRsaSha256();
    const data = "test data with buffer key";

    // Sign with string key
    signer.getSignature(data, privateKeyString, async (err, signature) => {
      if (err || !signature) return done(err);

      // Verify with buffer key
      const crypto = await import("crypto");
      const publicKeyObj = crypto.createPublicKey(publicKeyBuffer);
      const spkiPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

      signer.verifySignature(data, Buffer.from(spkiPem), signature, (verifyErr, isValid) => {
        if (verifyErr) return done(verifyErr);

        expect(isValid).to.be.true;
        done();
      });
    });
  });

  it("should accept KeyObject as private key for signing", function (done) {
    import("crypto")
      .then((crypto) => {
        const signer = new WebCryptoRsaSha256();
        const data = "test data with KeyObject";

        const privateKeyObj = crypto.createPrivateKey(privateKeyString);
        signer.getSignature(data, privateKeyObj, (err, signature) => {
          if (err) return done(err);

          expect(signature).to.be.a("string");
          if (signature) {
            expect(signature.length).to.be.greaterThan(0);
          }
          done();
        });
      })
      .catch(done);
  });

  it("should accept KeyObject as public key for verification", function (done) {
    import("crypto")
      .then((crypto) => {
        const signer = new WebCryptoRsaSha256();
        const data = "test data with KeyObject";

        // Sign with string key
        signer.getSignature(data, privateKeyString, (err, signature) => {
          if (err || !signature) return done(err);

          // Verify with KeyObject
          const publicKeyObj = crypto.createPublicKey(publicKeyString);

          signer.verifySignature(data, publicKeyObj, signature, (verifyErr, isValid) => {
            if (verifyErr) return done(verifyErr);

            expect(isValid).to.be.true;
            done();
          });
        });
      })
      .catch(done);
  });

  it("should accept secret KeyObject for HMAC signing", function (done) {
    import("crypto")
      .then((crypto) => {
        const signer = new WebCryptoHmacSha1();
        const data = "test data with secret KeyObject";

        // Create a secret KeyObject
        const secretKey = crypto.createSecretKey(
          Uint8Array.from(Buffer.from("my-hmac-secret-key")),
        );
        signer.getSignature(data, secretKey, (err, signature) => {
          if (err || !signature) return done(err);

          expect(signature).to.be.a("string");
          expect(signature.length).to.be.greaterThan(0);

          // Verify with same secret KeyObject
          signer.verifySignature(data, secretKey, signature, (verifyErr, isValid) => {
            if (verifyErr) return done(verifyErr);

            expect(isValid).to.be.true;
            done();
          });
        });
      })
      .catch(done);
  });

  it("should accept Uint8Array as key", function (done) {
    const signer = new WebCryptoRsaSha256();
    const data = "test data with Uint8Array";

    const privateKeyUint8 = new Uint8Array(privateKeyBuffer);
    signer.getSignature(data, privateKeyUint8, (err, signature) => {
      if (err) return done(err);

      expect(signature).to.be.a("string");
      if (signature) {
        expect(signature.length).to.be.greaterThan(0);
      }
      done();
    });
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
