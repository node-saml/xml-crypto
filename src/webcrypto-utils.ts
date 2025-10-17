/**
 * Utility functions for working with Web Crypto API
 */

/**
 * Convert a PEM string to an ArrayBuffer
 * @param pem PEM-encoded key (with or without headers)
 * @returns ArrayBuffer containing the binary key data
 */
export function pemToArrayBuffer(pem: string): ArrayBuffer {
  // Remove PEM headers and whitespace
  const pemContent = pem
    .replace(/-----BEGIN [A-Z ]+-----/, "")
    .replace(/-----END [A-Z ]+-----/, "")
    .replace(/\s/g, "");

  // Decode base64 to binary string
  const binaryString = atob(pemContent);

  // Convert binary string to ArrayBuffer
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }

  return bytes.buffer;
}

/**
 * Convert an ArrayBuffer to base64 string
 * @param buffer ArrayBuffer to convert
 * @returns Base64-encoded string
 */
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert a base64 string to ArrayBuffer
 * @param base64 Base64-encoded string
 * @returns ArrayBuffer
 */
export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Import a PEM-encoded RSA private key for signing
 * @param pem PEM-encoded private key
 * @param hashAlgorithm Hash algorithm name (e.g., "SHA-1", "SHA-256", "SHA-512")
 * @returns CryptoKey for signing
 */
export async function importRsaPrivateKey(
  pem: string | ArrayBuffer,
  hashAlgorithm: string,
): Promise<CryptoKey> {
  const keyData = typeof pem === "string" ? pemToArrayBuffer(pem) : pem;

  return await crypto.subtle.importKey(
    "pkcs8",
    keyData,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: { name: hashAlgorithm },
    },
    false,
    ["sign"],
  );
}

/**
 * Import a PEM-encoded RSA public key for verification
 * @param pem PEM-encoded public key or certificate
 * @param hashAlgorithm Hash algorithm name (e.g., "SHA-1", "SHA-256", "SHA-512")
 * @returns CryptoKey for verification
 */
export async function importRsaPublicKey(
  pem: string | ArrayBuffer,
  hashAlgorithm: string,
): Promise<CryptoKey> {
  let keyData: ArrayBuffer;

  if (typeof pem === "string") {
    // Check if this is a certificate
    if (pem.includes("BEGIN CERTIFICATE")) {
      // For certificates, we need to extract the public key
      // This is a basic implementation - for production use, consider using a proper ASN.1 parser
      // Web Crypto API doesn't support X.509 certificates directly
      // For now, we'll try to parse it as SPKI and provide a helpful error
      keyData = pemToArrayBuffer(pem);

      // Try to extract the public key from the certificate
      // This is a simplified approach and may not work for all certificates
      try {
        return await crypto.subtle.importKey(
          "spki",
          keyData,
          {
            name: "RSASSA-PKCS1-v1_5",
            hash: { name: hashAlgorithm },
          },
          false,
          ["verify"],
        );
      } catch (error) {
        throw new Error(
          "X.509 certificates are not directly supported by Web Crypto API. " +
            "Please extract the public key from the certificate and provide it in SPKI format, " +
            "or use Node.js crypto algorithms instead. " +
            `Original error: ${error}`,
        );
      }
    }
    keyData = pemToArrayBuffer(pem);
  } else {
    keyData = pem;
  }

  // Try importing as SPKI (SubjectPublicKeyInfo) format
  try {
    return await crypto.subtle.importKey(
      "spki",
      keyData,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: hashAlgorithm },
      },
      false,
      ["verify"],
    );
  } catch (error) {
    throw new Error(
      `Failed to import RSA public key. Please ensure the key is in SPKI format. ${error}`,
    );
  }
}

/**
 * Import an HMAC key
 * @param key Key material (string or ArrayBuffer)
 * @param hashAlgorithm Hash algorithm name (e.g., "SHA-1", "SHA-256", "SHA-512")
 * @returns CryptoKey for HMAC operations
 */
export async function importHmacKey(
  key: string | ArrayBuffer,
  hashAlgorithm: string,
): Promise<CryptoKey> {
  const keyData = typeof key === "string" ? new TextEncoder().encode(key) : key;

  return await crypto.subtle.importKey(
    "raw",
    keyData,
    {
      name: "HMAC",
      hash: { name: hashAlgorithm },
    },
    false,
    ["sign", "verify"],
  );
}
