import type { HashAlgorithm } from "./types";

/**
 * WebCrypto-based SHA-1 hash algorithm
 * Uses the Web Crypto API which is available in browsers and modern Node.js
 */
export class WebCryptoSha1 implements HashAlgorithm {
  getHash = async (xml: string): Promise<string> => {
    const encoder = new TextEncoder();
    const data = encoder.encode(xml);
    const hashBuffer = await crypto.subtle.digest("SHA-1", data);
    return this.arrayBufferToBase64(hashBuffer);
  };

  getAlgorithmName = (): string => {
    return "http://www.w3.org/2000/09/xmldsig#sha1";
  };

  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
}

/**
 * WebCrypto-based SHA-256 hash algorithm
 * Uses the Web Crypto API which is available in browsers and modern Node.js
 */
export class WebCryptoSha256 implements HashAlgorithm {
  getHash = async (xml: string): Promise<string> => {
    const encoder = new TextEncoder();
    const data = encoder.encode(xml);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return this.arrayBufferToBase64(hashBuffer);
  };

  getAlgorithmName = (): string => {
    return "http://www.w3.org/2001/04/xmlenc#sha256";
  };

  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
}

/**
 * WebCrypto-based SHA-512 hash algorithm
 * Uses the Web Crypto API which is available in browsers and modern Node.js
 */
export class WebCryptoSha512 implements HashAlgorithm {
  getHash = async (xml: string): Promise<string> => {
    const encoder = new TextEncoder();
    const data = encoder.encode(xml);
    const hashBuffer = await crypto.subtle.digest("SHA-512", data);
    return this.arrayBufferToBase64(hashBuffer);
  };

  getAlgorithmName = (): string => {
    return "http://www.w3.org/2001/04/xmlenc#sha512";
  };

  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
}
