import * as crypto from "crypto";
import {
  type BinaryLike,
  type KeyLike,
  type SignatureAlgorithm,
  createOptionalCallbackFunction,
} from "./types";

/**
 * `node:crypto` takes any `ArrayBufferView` but not a bare `ArrayBuffer`, which is what Web
 * Crypto produces. Wrap rather than copy: `Buffer.from` over the three arguments is a view.
 */
function toNodeData(data: BinaryLike): crypto.BinaryLike {
  return data instanceof ArrayBuffer ? Buffer.from(data) : data;
}

/**
 * The signature algorithm is looked up by a URI read from the document under inspection, so a
 * JavaScript caller can pair any key representation with any algorithm and the compiler never
 * sees it. Handed a `CryptoKey`, Node does not fail: it accepts it through the DEP0203 shim,
 * so the signature appears to verify against a key this algorithm never really supported.
 * Reject it here instead.
 *
 * @see https://github.com/node-saml/xml-crypto/issues/545
 */
function toNodeKey(key: KeyLike, algorithmName: string): crypto.KeyLike {
  if (typeof key === "string" || Buffer.isBuffer(key) || key instanceof crypto.KeyObject) {
    return key;
  }

  if (key instanceof Uint8Array) {
    return Buffer.from(key.buffer, key.byteOffset, key.byteLength);
  }

  throw new Error(
    `${algorithmName} needs a key that node:crypto accepts: a string, a Buffer, a Uint8Array, or a KeyObject`,
  );
}

export class RsaSha1 implements SignatureAlgorithm<crypto.KeyLike | Uint8Array> {
  getSignature = createOptionalCallbackFunction(
    (signedInfo: BinaryLike, privateKey: crypto.KeyLike | Uint8Array): string => {
      const signer = crypto.createSign("RSA-SHA1");
      signer.update(toNodeData(signedInfo));
      const res = signer.sign(toNodeKey(privateKey, "RsaSha1"), "base64");

      return res;
    },
  );

  verifySignature = createOptionalCallbackFunction(
    (material: string, key: crypto.KeyLike | Uint8Array, signatureValue: string): boolean => {
      const verifier = crypto.createVerify("RSA-SHA1");
      verifier.update(material);
      const res = verifier.verify(toNodeKey(key, "RsaSha1"), signatureValue, "base64");

      return res;
    },
  );

  getAlgorithmName = () => {
    return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  };
}

export class RsaSha256 implements SignatureAlgorithm<crypto.KeyLike | Uint8Array> {
  getSignature = createOptionalCallbackFunction(
    (signedInfo: BinaryLike, privateKey: crypto.KeyLike | Uint8Array): string => {
      const signer = crypto.createSign("RSA-SHA256");
      signer.update(toNodeData(signedInfo));
      const res = signer.sign(toNodeKey(privateKey, "RsaSha256"), "base64");

      return res;
    },
  );

  verifySignature = createOptionalCallbackFunction(
    (material: string, key: crypto.KeyLike | Uint8Array, signatureValue: string): boolean => {
      const verifier = crypto.createVerify("RSA-SHA256");
      verifier.update(material);
      const res = verifier.verify(toNodeKey(key, "RsaSha256"), signatureValue, "base64");

      return res;
    },
  );

  getAlgorithmName = () => {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  };
}

export class RsaSha256Mgf1 implements SignatureAlgorithm<string | Buffer> {
  getSignature = createOptionalCallbackFunction(
    (signedInfo: BinaryLike, privateKey: string | Buffer): string => {
      if (!(typeof privateKey === "string" || Buffer.isBuffer(privateKey))) {
        throw new Error("keys must be strings or buffers");
      }
      const signer = crypto.createSign("RSA-SHA256");
      signer.update(toNodeData(signedInfo));
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
    (material: string, key: string | Buffer, signatureValue: string): boolean => {
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

export class RsaSha512 implements SignatureAlgorithm<crypto.KeyLike | Uint8Array> {
  getSignature = createOptionalCallbackFunction(
    (signedInfo: BinaryLike, privateKey: crypto.KeyLike | Uint8Array): string => {
      const signer = crypto.createSign("RSA-SHA512");
      signer.update(toNodeData(signedInfo));
      const res = signer.sign(toNodeKey(privateKey, "RsaSha512"), "base64");

      return res;
    },
  );

  verifySignature = createOptionalCallbackFunction(
    (material: string, key: crypto.KeyLike | Uint8Array, signatureValue: string): boolean => {
      const verifier = crypto.createVerify("RSA-SHA512");
      verifier.update(material);
      const res = verifier.verify(toNodeKey(key, "RsaSha512"), signatureValue, "base64");

      return res;
    },
  );

  getAlgorithmName = () => {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
  };
}

export class HmacSha1 implements SignatureAlgorithm<crypto.KeyLike | Uint8Array> {
  getSignature = createOptionalCallbackFunction(
    (signedInfo: BinaryLike, privateKey: crypto.KeyLike | Uint8Array): string => {
      const signer = crypto.createHmac("SHA1", toNodeKey(privateKey, "HmacSha1"));
      signer.update(toNodeData(signedInfo));
      const res = signer.digest("base64");

      return res;
    },
  );

  verifySignature = createOptionalCallbackFunction(
    (material: string, key: crypto.KeyLike | Uint8Array, signatureValue: string): boolean => {
      const verifier = crypto.createHmac("SHA1", toNodeKey(key, "HmacSha1"));
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
    return "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
  };
}
