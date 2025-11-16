import * as crypto from "crypto";
import { type SignatureAlgorithm, createOptionalCallbackFunction } from "./types";
import { XMLDSIG_URIS } from "./xmldsig-uris";

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
    return XMLDSIG_URIS.SIGNATURE_ALGORITHMS.RSA_SHA1;
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
    return XMLDSIG_URIS.SIGNATURE_ALGORITHMS.RSA_SHA256;
  };
}

export class RsaSha256Mgf1 implements SignatureAlgorithm {
  getSignature = createOptionalCallbackFunction(
    (signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string => {
      if (!(typeof privateKey === "string" || Buffer.isBuffer(privateKey))) {
        throw new Error("keys must be strings or buffers");
      }
      const signer = crypto.createSign("RSA-SHA256");
      signer.update(signedInfo);
      const res = signer.sign(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
        },
        "base64",
      );

      return res;
    },
  );

  verifySignature = createOptionalCallbackFunction(
    (material: string, key: crypto.KeyLike, signatureValue: string): boolean => {
      if (!(typeof key === "string" || Buffer.isBuffer(key))) {
        throw new Error("keys must be strings or buffers");
      }
      const verifier = crypto.createVerify("RSA-SHA256");
      verifier.update(material);
      const res = verifier.verify(
        {
          key: key,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
        },
        signatureValue,
        "base64",
      );

      return res;
    },
  );

  getAlgorithmName = () => {
    return XMLDSIG_URIS.SIGNATURE_ALGORITHMS.RSA_SHA256_MGF1;
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
    return XMLDSIG_URIS.SIGNATURE_ALGORITHMS.RSA_SHA512;
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

      // Use constant-time comparison to prevent timing attacks (CWE-208)
      // See: https://github.com/node-saml/xml-crypto/issues/522
      try {
        return crypto.timingSafeEqual(
          Buffer.from(res, "base64"),
          Buffer.from(signatureValue, "base64"),
        );
      } catch (e) {
        // timingSafeEqual throws if buffer lengths don't match
        return false;
      }
    },
  );

  getAlgorithmName = () => {
    return XMLDSIG_URIS.SIGNATURE_ALGORITHMS.HMAC_SHA1;
  };
}
