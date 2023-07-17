import * as crypto from "crypto";
import type { HashAlgorithm } from "./types";

export class Sha1 implements HashAlgorithm {
  getHash = function (xml) {
    const shasum = crypto.createHash("sha1");
    shasum.update(xml, "utf8");
    const res = shasum.digest("base64");
    return res;
  };

  getAlgorithmName = function () {
    return "http://www.w3.org/2000/09/xmldsig#sha1";
  };
}

export class Sha256 implements HashAlgorithm {
  getHash = function (xml) {
    const shasum = crypto.createHash("sha256");
    shasum.update(xml, "utf8");
    const res = shasum.digest("base64");
    return res;
  };

  getAlgorithmName = function () {
    return "http://www.w3.org/2001/04/xmlenc#sha256";
  };
}

export class Sha512 implements HashAlgorithm {
  getHash = function (xml) {
    const shasum = crypto.createHash("sha512");
    shasum.update(xml, "utf8");
    const res = shasum.digest("base64");
    return res;
  };

  getAlgorithmName = function () {
    return "http://www.w3.org/2001/04/xmlenc#sha512";
  };
}
