const crypto = require("crypto");

/**
 * @type { import("../index.d.ts").HashAlgorithm}
 */
class Sha1 {
  constructor() {
    this.getHash = function (xml) {
      const shasum = crypto.createHash("sha1");
      shasum.update(xml, "utf8");
      const res = shasum.digest("base64");
      return res;
    };

    this.getAlgorithmName = function () {
      return "http://www.w3.org/2000/09/xmldsig#sha1";
    };
  }
}

/**
 * @type { import("../index.d.ts").HashAlgorithm}
 */
class Sha256 {
  constructor() {
    this.getHash = function (xml) {
      const shasum = crypto.createHash("sha256");
      shasum.update(xml, "utf8");
      const res = shasum.digest("base64");
      return res;
    };

    this.getAlgorithmName = function () {
      return "http://www.w3.org/2001/04/xmlenc#sha256";
    };
  }
}

/**
 * @type { import("../index.d.ts").HashAlgorithm}
 */
class Sha512 {
  constructor() {
    this.getHash = function (xml) {
      const shasum = crypto.createHash("sha512");
      shasum.update(xml, "utf8");
      const res = shasum.digest("base64");
      return res;
    };

    this.getAlgorithmName = function () {
      return "http://www.w3.org/2001/04/xmlenc#sha512";
    };
  }
}

module.exports = {
  Sha1,
  Sha256,
  Sha512,
};
