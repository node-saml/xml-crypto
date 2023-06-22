const crypto = require("crypto");

/**
 * @type { import("../index.d.ts").SignatureAlgorithm}
 */
class RsaSha1 {
  constructor() {
    /**
     * Sign the given string using the given key
     *
     */
    this.getSignature = function (signedInfo, privateKey, callback) {
      const signer = crypto.createSign("RSA-SHA1");
      signer.update(signedInfo);
      const res = signer.sign(privateKey, "base64");
      if (callback) {
        callback(null, res);
      }
      return res;
    };

    /**
     * Verify the given signature of the given string using key
     *
     */
    this.verifySignature = function (str, key, signatureValue, callback) {
      const verifier = crypto.createVerify("RSA-SHA1");
      verifier.update(str);
      const res = verifier.verify(key, signatureValue, "base64");
      if (callback) {
        callback(null, res);
      }
      return res;
    };

    this.getAlgorithmName = function () {
      return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    };
  }
}

/**
 * @type { import("../index.d.ts").SignatureAlgorithm} SignatureAlgorithm
 */
class RsaSha256 {
  constructor() {
    this.getSignature = function (signedInfo, privateKey, callback) {
      const signer = crypto.createSign("RSA-SHA256");
      signer.update(signedInfo);
      const res = signer.sign(privateKey, "base64");
      if (callback) {
        callback(null, res);
      }
      return res;
    };

    this.verifySignature = function (str, key, signatureValue, callback) {
      const verifier = crypto.createVerify("RSA-SHA256");
      verifier.update(str);
      const res = verifier.verify(key, signatureValue, "base64");
      if (callback) {
        callback(null, res);
      }
      return res;
    };

    this.getAlgorithmName = function () {
      return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    };
  }
}

/**
 * @type { import("../index.d.ts").SignatureAlgorithm}
 */
class RsaSha512 {
  constructor() {
    this.getSignature = function (signedInfo, privateKey, callback) {
      const signer = crypto.createSign("RSA-SHA512");
      signer.update(signedInfo);
      const res = signer.sign(privateKey, "base64");
      if (callback) {
        callback(null, res);
      }
      return res;
    };

    this.verifySignature = function (str, key, signatureValue, callback) {
      const verifier = crypto.createVerify("RSA-SHA512");
      verifier.update(str);
      const res = verifier.verify(key, signatureValue, "base64");
      if (callback) {
        callback(null, res);
      }
      return res;
    };

    this.getAlgorithmName = function () {
      return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    };
  }
}

/**
 * @type { import("../index.d.ts").SignatureAlgorithm}
 */
class HmacSha1 {
  constructor() {
    this.verifySignature = function (str, key, signatureValue) {
      const verifier = crypto.createHmac("SHA1", key);
      verifier.update(str);
      const res = verifier.digest("base64");
      return res === signatureValue;
    };

    this.getAlgorithmName = function () {
      return "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
    };

    this.getSignature = function (signedInfo, privateKey) {
      const verifier = crypto.createHmac("SHA1", privateKey);
      verifier.update(signedInfo);
      const res = verifier.digest("base64");
      return res;
    };
  }
}

module.exports = {
  RsaSha1,
  RsaSha256,
  RsaSha512,
  HmacSha1,
};
