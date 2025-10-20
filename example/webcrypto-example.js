/**
 * Example of using xml-crypto with Web Crypto API (callback-based)
 *
 * This example demonstrates how to use the WebCrypto implementations
 * to sign and verify XML signatures using callbacks.
 *
 * This works in:
 * - Modern browsers
 * - Node.js 15.0.0+
 * - Deno
 * - Any environment with Web Crypto API support
 */

import { SignedXml, WebCryptoRsaSha256, WebCryptoSha256 } from "../lib/index.js";
import { readFileSync } from "fs";
import { createPublicKey } from "crypto";
import { DOMParser } from "@xmldom/xmldom";

/**
 * Helper function to convert X.509 certificate to SPKI format public key
 * Note: This uses Node.js crypto for conversion. In a pure browser environment,
 * you would need to extract the public key beforehand or use a library.
 */
function extractPublicKeyFromCertificate(certPem) {
  try {
    const publicKey = createPublicKey(certPem);
    return publicKey.export({
      type: "spki",
      format: "pem",
    });
  } catch (error) {
    throw new Error(`Failed to extract public key from certificate: ${error.message}`);
  }
}

function signXml(callback) {
  console.log("=== Signing XML with WebCrypto ===\n");

  const xml = "<library><book><name>Harry Potter</name></book></library>";
  console.log("Original XML:", xml);

  // Load private key
  const privateKey = readFileSync("./example/client.pem", "utf8");

  // Create signature
  const sig = new SignedXml();
  sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
  sig.privateKey = privateKey;

  // Add reference
  sig.addReference({
    xpath: "//*[local-name(.)='book']",
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
  });

  // Register WebCrypto algorithms
  sig.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
  sig.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] = WebCryptoRsaSha256;

  // Compute signature with callback
  sig.computeSignature(xml, (err, signedXmlObj) => {
    if (err) {
      return callback(err);
    }

    const signedXml = signedXmlObj.getSignedXml();
    console.log("\nSigned XML:", signedXml);
    callback(null, signedXml);
  });
}

function verifyXml(signedXml, callback) {
  console.log("\n=== Verifying XML Signature with WebCrypto ===\n");

  // Load public certificate and extract the public key in SPKI format
  const certPem = readFileSync("./example/client_public.pem", "utf8");
  const publicKeySpki = extractPublicKeyFromCertificate(certPem);

  console.log("Note: Extracted public key from X.509 certificate");

  // Create verification object
  const sig = new SignedXml();
  sig.publicCert = publicKeySpki; // Use SPKI format public key

  // Register WebCrypto algorithms
  sig.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
  sig.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] = WebCryptoRsaSha256;

  // We need to load the signature before verification:
  // 1. Parse the signed XML to get a DOM
  // 2. Find the <Signature> element within it
  // 3. Load that specific signature node
  const doc = new DOMParser().parseFromString(signedXml);
  const signature = sig.findSignatures(doc)[0];
  sig.loadSignature(signature);

  // Verify with callback
  sig.checkSignature(signedXml, (err, isValid) => {
    if (err) {
      console.error("Signature verification failed:", err.message);
      return callback(err);
    }
    console.log("Signature is valid:", isValid);
    callback(null, isValid);
  });
}

function main() {
  // Sign the XML
  signXml((err, signedXml) => {
    if (err) {
      console.error("\n❌ Error during signing:", err);
      process.exit(1);
    }

    // Verify the signature
    verifyXml(signedXml, (err, isValid) => {
      if (err) {
        console.error("\n❌ Error during verification:", err);
        process.exit(1);
      }

      if (isValid) {
        console.log("\n✅ Success! XML was signed and verified using WebCrypto API");
      } else {
        console.log("\n❌ Verification failed");
        process.exit(1);
      }
    });
  });
}

// Run the example
main();
