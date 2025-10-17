import * as crypto from "crypto";
import {
  type SignatureAlgorithm,
  type BinaryLike,
  type KeyLike,
  createOptionalCallbackFunction,
} from "./types";

export class RsaSha1 implements SignatureAlgorithm {
  getSignature = createOptionalCallbackFunction(
    (signedInfo: BinaryLike, privateKey: KeyLike): string => {
      const signer = crypto.createSign("RSA-SHA1");
      signer.update(signedInfo as crypto.BinaryLike);
      const res = signer.sign(privateKey as crypto.KeyLike, "base64");

      return res;
    },
  );

  verifySignature = createOptionalCallbackFunction(
    (material: string, key: KeyLike, signatureValue: string): boolean => {
      const verifier = crypto.createVerify("RSA-SHA1");
      verifier.update(material);
      const res = verifier.verify(key as crypto.KeyLike, signatureValue, "base64");

      return res;
    },
  );

  getAlgorithmName = () => {
    return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  };
}

export class RsaSha256 implements SignatureAlgorithm {
  getSignature = createOptionalCallbackFunction(
    (signedInfo: BinaryLike, privateKey: KeyLike): string => {
      const signer = crypto.createSign("RSA-SHA256");
      signer.update(signedInfo as crypto.BinaryLike);
      const res = signer.sign(privateKey as crypto.KeyLike, "base64");

      return res;
    },
  );

  verifySignature = createOptionalCallbackFunction(
    (material: string, key: KeyLike, signatureValue: string): boolean => {
      const verifier = crypto.createVerify("RSA-SHA256");
      verifier.update(material);
      const res = verifier.verify(key as crypto.KeyLike, signatureValue, "base64");

      return res;
    },
  );

  getAlgorithmName = () => {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
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
    return "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
  };
}

export class RsaSha512 implements SignatureAlgorithm {
  getSignature = createOptionalCallbackFunction(
    (signedInfo: BinaryLike, privateKey: KeyLike): string => {
      const signer = crypto.createSign("RSA-SHA512");
      signer.update(signedInfo as crypto.BinaryLike);
      const res = signer.sign(privateKey as crypto.KeyLike, "base64");

      return res;
    },
  );

  verifySignature = createOptionalCallbackFunction(
    (material: string, key: KeyLike, signatureValue: string): boolean => {
      const verifier = crypto.createVerify("RSA-SHA512");
      verifier.update(material);
      const res = verifier.verify(key as crypto.KeyLike, signatureValue, "base64");

      return res;
    },
  );

  getAlgorithmName = () => {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
  };
}

export class HmacSha1 implements SignatureAlgorithm {
  getSignature = createOptionalCallbackFunction(
    (signedInfo: BinaryLike, privateKey: KeyLike): string => {
      const signer = crypto.createHmac("SHA1", privateKey as crypto.BinaryLike | crypto.KeyObject);
      signer.update(signedInfo as crypto.BinaryLike);
      const res = signer.digest("base64");

      return res;
    },
  );

  verifySignature = createOptionalCallbackFunction(
    (material: string, key: KeyLike, signatureValue: string): boolean => {
      const verifier = crypto.createHmac("SHA1", key as crypto.BinaryLike | crypto.KeyObject);
      verifier.update(material);
      const res = verifier.digest("base64");

      return res === signatureValue;
    },
  );

  getAlgorithmName = () => {
    return "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
  };
}
