import * as crypto from "crypto";
import { type SignatureAlgorithm, createOptionalCallbackFunction } from "./types";

export class RsaSha1 implements SignatureAlgorithm {
  getSignature = createOptionalCallbackFunction(
    (signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string => {
      const signer = crypto.createSign("RSA-SHA1");
      signer.update(signedInfo);
      const res = signer.sign(privateKey, "base64");

      return res;
    },
  );

  verifySignature = createOptionalCallbackFunction(
    (material: string, key: crypto.KeyLike, signatureValue: string): boolean => {
      const verifier = crypto.createVerify("RSA-SHA1");
      verifier.update(material);
      const res = verifier.verify(key, signatureValue, "base64");

      return res;
    },
  );

  getAlgorithmName = () => {
    return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  };
}

export class RsaSha256 implements SignatureAlgorithm {
  getSignature = createOptionalCallbackFunction(
    (signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string => {
      const signer = crypto.createSign("RSA-SHA256");
      signer.update(signedInfo);
      const res = signer.sign(privateKey, "base64");

      return res;
    },
  );

  verifySignature = createOptionalCallbackFunction(
    (material: string, key: crypto.KeyLike, signatureValue: string): boolean => {
      const verifier = crypto.createVerify("RSA-SHA256");
      verifier.update(material);
      const res = verifier.verify(key, signatureValue, "base64");

      return res;
    },
  );

  getAlgorithmName = () => {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  };
}

export class RsaSha512 implements SignatureAlgorithm {
  getSignature = createOptionalCallbackFunction(
    (signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string => {
      const signer = crypto.createSign("RSA-SHA512");
      signer.update(signedInfo);
      const res = signer.sign(privateKey, "base64");

      return res;
    },
  );

  verifySignature = createOptionalCallbackFunction(
    (material: string, key: crypto.KeyLike, signatureValue: string): boolean => {
      const verifier = crypto.createVerify("RSA-SHA512");
      verifier.update(material);
      const res = verifier.verify(key, signatureValue, "base64");

      return res;
    },
  );

  getAlgorithmName = () => {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
  };
}

export class HmacSha1 implements SignatureAlgorithm {
  getSignature = createOptionalCallbackFunction(
    (signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string => {
      const signer = crypto.createHmac("SHA1", privateKey);
      signer.update(signedInfo);
      const res = signer.digest("base64");

      return res;
    },
  );

  verifySignature = createOptionalCallbackFunction(
    (material: string, key: crypto.KeyLike, signatureValue: string): boolean => {
      const verifier = crypto.createHmac("SHA1", key);
      verifier.update(material);
      const res = verifier.digest("base64");

      return res === signatureValue;
    },
  );

  getAlgorithmName = () => {
    return "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
  };
}
