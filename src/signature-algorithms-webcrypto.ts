import {
  type BinaryLike,
  type ErrorFirstCallback,
  type KeyLike,
  type SignatureAlgorithm,
} from "./types";
import {
  importRsaPrivateKey,
  importRsaPublicKey,
  importHmacKey,
  arrayBufferToBase64,
  base64ToArrayBuffer,
} from "./webcrypto-utils";
import * as nodeCrypto from "crypto";

/**
 * Check if a value is a CryptoKey (not a KeyObject)
 * Guards against ReferenceError in environments without Web Crypto API
 */
function isCryptoKey(key: unknown): key is CryptoKey {
  // CryptoKey has specific properties that KeyObject doesn't have
  return (
    (typeof CryptoKey !== "undefined" && key instanceof CryptoKey) ||
    (typeof key === "object" &&
      key !== null &&
      "type" in key &&
      "algorithm" in key &&
      "extractable" in key &&
      "usages" in key &&
      !("export" in key)) // KeyObject has export, CryptoKey doesn't
  );
}

/**
 * Check if a value is a Node.js Buffer without directly referencing the Buffer global.
 * This is browser-safe: it never calls Buffer.isBuffer() or accesses the Buffer global,
 * preventing ReferenceError in environments where Buffer is not defined.
 * In browsers, this will always return false; in Node.js, it correctly identifies Buffers.
 */
function isBuffer(value: unknown): value is Uint8Array {
  // Safe: checks constructor name without accessing Buffer global
  return value instanceof Uint8Array && value.constructor.name === "Buffer";
}

/**
 * Check if a Uint8Array/Buffer contains valid UTF-8 text (like PEM format).
 * This helps us distinguish between text-based keys (PEM) and binary keys (DER, raw bytes).
 */
function isPemText(data: Uint8Array): boolean {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(data);
    // Check if it looks like PEM format
    return text.includes("-----BEGIN") && text.includes("-----END");
  } catch {
    // Not valid UTF-8 text
    return false;
  }
}

/**
 * Normalize various key input types to a format suitable for Web Crypto API.
 * Returns either a PEM string (for RSA keys) or ArrayBuffer (for raw binary keys like HMAC).
 * Preserves binary data without UTF-8 mangling.
 */
function normalizeKey(key: unknown): string | ArrayBuffer {
  if (typeof key === "string") {
    return key;
  }

  // Handle Uint8Array or Buffer
  if (key instanceof Uint8Array || isBuffer(key)) {
    const uint8Array = key as Uint8Array;

    // Check if this contains PEM text (common case: Buffer wrapping PEM string)
    if (isPemText(uint8Array)) {
      // Decode as UTF-8 text
      return new TextDecoder("utf-8").decode(uint8Array);
    }

    // Otherwise, preserve as binary (for DER keys, raw HMAC keys, etc.)
    const buffer = new ArrayBuffer(uint8Array.byteLength);
    const view = new Uint8Array(buffer);
    view.set(uint8Array);
    return buffer;
  }

  // Handle ArrayBuffer - return as-is (assume binary)
  if (key instanceof ArrayBuffer) {
    return key;
  }

  // Handle Node.js KeyObject
  if (
    typeof key === "object" &&
    key !== null &&
    "type" in key &&
    "export" in key &&
    typeof (key as { export: unknown }).export === "function" &&
    !("algorithm" in key && "extractable" in key && "usages" in key) // Not a CryptoKey
  ) {
    const keyObject = key as nodeCrypto.KeyObject;
    if (keyObject.type === "private") {
      return keyObject.export({ type: "pkcs8", format: "pem" }) as string;
    } else if (keyObject.type === "public") {
      return keyObject.export({ type: "spki", format: "pem" }) as string;
    } else if (keyObject.type === "secret") {
      // For secret keys (HMAC), export as buffer and preserve binary data
      const secretBuffer = keyObject.export();
      // Convert Node.js Buffer to ArrayBuffer properly
      // Note: Buffer.buffer may be a pooled ArrayBuffer, so we need to copy the data
      const arrayBuffer = new ArrayBuffer(secretBuffer.byteLength);
      const view = new Uint8Array(arrayBuffer);
      // Create a proper Uint8Array view of the Buffer to ensure compatibility
      const bytes = new Uint8Array(
        secretBuffer.buffer,
        secretBuffer.byteOffset,
        secretBuffer.byteLength,
      );
      view.set(bytes);
      return arrayBuffer;
    }
  }
  throw new Error(
    "Unsupported key type. Expected string (PEM), Buffer, Uint8Array, ArrayBuffer, KeyObject, or CryptoKey",
  );
}

/**
 * Convert various input types to ArrayBuffer for Web Crypto API.
 *
 * BROWSER SAFETY: This function never references the global Buffer object directly.
 * It uses the browser-safe isBuffer() helper which only checks constructor.name,
 * preventing ReferenceError in environments where Buffer is not defined.
 */
function toArrayBuffer(data: unknown): ArrayBuffer {
  if (typeof data === "string") {
    return new TextEncoder().encode(data).buffer;
  }
  if (data instanceof ArrayBuffer) {
    return data;
  }
  // Browser-safe: isBuffer() never calls Buffer.isBuffer() or accesses Buffer global
  if (data instanceof Uint8Array || isBuffer(data)) {
    // Create a new ArrayBuffer from the Uint8Array/Buffer
    const buffer = new ArrayBuffer((data as Uint8Array).byteLength);
    const view = new Uint8Array(buffer);
    view.set(data as Uint8Array);
    return buffer;
  }
  throw new Error("Unsupported data type");
}

/**
 * WebCrypto-based RSA-SHA1 signature algorithm
 * Uses the Web Crypto API which is available in browsers and modern Node.js
 */
export class WebCryptoRsaSha1 implements SignatureAlgorithm {
  getSignature(signedInfo: BinaryLike, privateKey: KeyLike): string;
  getSignature(
    signedInfo: BinaryLike,
    privateKey: KeyLike,
    callback: ErrorFirstCallback<string>,
  ): void;
  getSignature(
    signedInfo: BinaryLike,
    privateKey: KeyLike,
    callback?: ErrorFirstCallback<string>,
  ): string | void {
    if (!callback) {
      throw new Error("WebCrypto algorithms require a callback");
    }

    (async () => {
      // If already a CryptoKey, use it directly
      let key: CryptoKey;
      if (isCryptoKey(privateKey)) {
        key = privateKey;
      } else {
        // Normalize key (handles Buffer, KeyObject, etc.)
        const normalizedKey = normalizeKey(privateKey);
        key = await importRsaPrivateKey(normalizedKey, "SHA-1");
      }

      const data = toArrayBuffer(signedInfo);
      const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data);
      return arrayBufferToBase64(signature);
    })()
      .then((result) => callback(null, result))
      .catch((err) => callback(err instanceof Error ? err : new Error("Unknown error")));
  }

  verifySignature(material: string, key: KeyLike, signatureValue: string): boolean;
  verifySignature(
    material: string,
    key: KeyLike,
    signatureValue: string,
    callback: ErrorFirstCallback<boolean>,
  ): void;
  verifySignature(
    material: string,
    key: KeyLike,
    signatureValue: string,
    callback?: ErrorFirstCallback<boolean>,
  ): boolean | void {
    if (!callback) {
      throw new Error("WebCrypto algorithms require a callback");
    }

    (async () => {
      // If already a CryptoKey, use it directly
      let publicKey: CryptoKey;
      if (isCryptoKey(key)) {
        publicKey = key;
      } else {
        // Normalize key (handles Buffer, KeyObject, etc.)
        const normalizedKey = normalizeKey(key);
        publicKey = await importRsaPublicKey(normalizedKey, "SHA-1");
      }

      const data = new TextEncoder().encode(material);
      const signature = base64ToArrayBuffer(signatureValue);
      return await crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signature, data);
    })()
      .then((result) => callback(null, result))
      .catch((err) => callback(err instanceof Error ? err : new Error("Unknown error")));
  }

  getAlgorithmName(): string {
    return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  }
}

/**
 * WebCrypto-based RSA-SHA256 signature algorithm
 * Uses the Web Crypto API which is available in browsers and modern Node.js
 */
export class WebCryptoRsaSha256 implements SignatureAlgorithm {
  getSignature(signedInfo: BinaryLike, privateKey: KeyLike): string;
  getSignature(
    signedInfo: BinaryLike,
    privateKey: KeyLike,
    callback: ErrorFirstCallback<string>,
  ): void;
  getSignature(
    signedInfo: BinaryLike,
    privateKey: KeyLike,
    callback?: ErrorFirstCallback<string>,
  ): string | void {
    if (!callback) {
      throw new Error("WebCrypto algorithms require a callback");
    }

    (async () => {
      // If already a CryptoKey, use it directly
      let key: CryptoKey;
      if (isCryptoKey(privateKey)) {
        key = privateKey;
      } else {
        // Normalize key (handles Buffer, KeyObject, etc.)
        const normalizedKey = normalizeKey(privateKey);
        key = await importRsaPrivateKey(normalizedKey, "SHA-256");
      }

      const data = toArrayBuffer(signedInfo);
      const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data);
      return arrayBufferToBase64(signature);
    })()
      .then((result) => callback(null, result))
      .catch((err) => callback(err instanceof Error ? err : new Error("Unknown error")));
  }

  verifySignature(material: string, key: KeyLike, signatureValue: string): boolean;
  verifySignature(
    material: string,
    key: KeyLike,
    signatureValue: string,
    callback: ErrorFirstCallback<boolean>,
  ): void;
  verifySignature(
    material: string,
    key: KeyLike,
    signatureValue: string,
    callback?: ErrorFirstCallback<boolean>,
  ): boolean | void {
    if (!callback) {
      throw new Error("WebCrypto algorithms require a callback");
    }

    (async () => {
      // If already a CryptoKey, use it directly
      let publicKey: CryptoKey;
      if (isCryptoKey(key)) {
        publicKey = key;
      } else {
        // Normalize key (handles Buffer, KeyObject, etc.)
        const normalizedKey = normalizeKey(key);
        publicKey = await importRsaPublicKey(normalizedKey, "SHA-256");
      }

      const data = new TextEncoder().encode(material);
      const signature = base64ToArrayBuffer(signatureValue);
      return await crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signature, data);
    })()
      .then((result) => callback(null, result))
      .catch((err) => callback(err instanceof Error ? err : new Error("Unknown error")));
  }

  getAlgorithmName(): string {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  }
}

/**
 * WebCrypto-based RSA-SHA512 signature algorithm
 * Uses the Web Crypto API which is available in browsers and modern Node.js
 */
export class WebCryptoRsaSha512 implements SignatureAlgorithm {
  getSignature(signedInfo: BinaryLike, privateKey: KeyLike): string;
  getSignature(
    signedInfo: BinaryLike,
    privateKey: KeyLike,
    callback: ErrorFirstCallback<string>,
  ): void;
  getSignature(
    signedInfo: BinaryLike,
    privateKey: KeyLike,
    callback?: ErrorFirstCallback<string>,
  ): string | void {
    if (!callback) {
      throw new Error("WebCrypto algorithms require a callback");
    }

    (async () => {
      // If already a CryptoKey, use it directly
      let key: CryptoKey;
      if (isCryptoKey(privateKey)) {
        key = privateKey;
      } else {
        // Normalize key (handles Buffer, KeyObject, etc.)
        const normalizedKey = normalizeKey(privateKey);
        key = await importRsaPrivateKey(normalizedKey, "SHA-512");
      }

      const data = toArrayBuffer(signedInfo);
      const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data);
      return arrayBufferToBase64(signature);
    })()
      .then((result) => callback(null, result))
      .catch((err) => callback(err instanceof Error ? err : new Error("Unknown error")));
  }

  verifySignature(material: string, key: KeyLike, signatureValue: string): boolean;
  verifySignature(
    material: string,
    key: KeyLike,
    signatureValue: string,
    callback: ErrorFirstCallback<boolean>,
  ): void;
  verifySignature(
    material: string,
    key: KeyLike,
    signatureValue: string,
    callback?: ErrorFirstCallback<boolean>,
  ): boolean | void {
    if (!callback) {
      throw new Error("WebCrypto algorithms require a callback");
    }

    (async () => {
      // If already a CryptoKey, use it directly
      let publicKey: CryptoKey;
      if (isCryptoKey(key)) {
        publicKey = key;
      } else {
        // Normalize key (handles Buffer, KeyObject, etc.)
        const normalizedKey = normalizeKey(key);
        publicKey = await importRsaPublicKey(normalizedKey, "SHA-512");
      }

      const data = toArrayBuffer(material);
      const signature = base64ToArrayBuffer(signatureValue);
      return await crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signature, data);
    })()
      .then((result) => callback(null, result))
      .catch((err) => callback(err instanceof Error ? err : new Error("Unknown error")));
  }

  getAlgorithmName(): string {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
  }
}

/**
 * WebCrypto-based HMAC-SHA1 signature algorithm
 * Uses the Web Crypto API which is available in browsers and modern Node.js
 */
export class WebCryptoHmacSha1 implements SignatureAlgorithm {
  getSignature(signedInfo: BinaryLike, privateKey: KeyLike): string;
  getSignature(
    signedInfo: BinaryLike,
    privateKey: KeyLike,
    callback: ErrorFirstCallback<string>,
  ): void;
  getSignature(
    signedInfo: BinaryLike,
    privateKey: KeyLike,
    callback?: ErrorFirstCallback<string>,
  ): string | void {
    if (!callback) {
      throw new Error("WebCrypto algorithms require a callback");
    }

    (async () => {
      // If already a CryptoKey, use it directly
      let key: CryptoKey;
      if (isCryptoKey(privateKey)) {
        key = privateKey;
      } else {
        // Normalize key (handles Buffer, KeyObject, etc.)
        // HMAC keys can be binary (ArrayBuffer) or string
        const normalizedKey = normalizeKey(privateKey);
        key = await importHmacKey(normalizedKey, "SHA-1");
      }

      const data = toArrayBuffer(signedInfo);
      const signature = await crypto.subtle.sign("HMAC", key, data);
      return arrayBufferToBase64(signature);
    })()
      .then((result) => callback(null, result))
      .catch((err) => callback(err instanceof Error ? err : new Error("Unknown error")));
  }

  verifySignature(material: string, key: KeyLike, signatureValue: string): boolean;
  verifySignature(
    material: string,
    key: KeyLike,
    signatureValue: string,
    callback: ErrorFirstCallback<boolean>,
  ): void;
  verifySignature(
    material: string,
    key: KeyLike,
    signatureValue: string,
    callback?: ErrorFirstCallback<boolean>,
  ): boolean | void {
    if (!callback) {
      throw new Error("WebCrypto algorithms require a callback");
    }

    (async () => {
      // If already a CryptoKey, use it directly
      let hmacKey: CryptoKey;
      if (isCryptoKey(key)) {
        hmacKey = key;
      } else {
        // Normalize key (handles Buffer, KeyObject, etc.)
        // HMAC keys can be binary (ArrayBuffer) or string
        const normalizedKey = normalizeKey(key);
        hmacKey = await importHmacKey(normalizedKey, "SHA-1");
      }

      const data = new TextEncoder().encode(material);
      const signature = base64ToArrayBuffer(signatureValue);

      // Use crypto.subtle.verify for constant-time comparison (prevents timing attacks)
      return await crypto.subtle.verify("HMAC", hmacKey, signature, data);
    })()
      .then((result) => callback(null, result))
      .catch((err) => callback(err instanceof Error ? err : new Error("Unknown error")));
  }

  getAlgorithmName(): string {
    return "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
  }
}
