/**
 * Example of using xml-crypto with Web Crypto API
 *
 * This example demonstrates how to use the WebCrypto implementations
 * to sign and verify XML signatures without Node.js crypto dependencies.
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

async function signXml() {
  console.log("=== Signing XML with WebCrypto ===\n");

  const xml = "<library><book><name>Harry Potter</name></book></library>";
  console.log("Original XML:", xml);

  // Load private key
  const privateKey = readFileSync("./client.pem", "utf8");

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

  // Compute signature asynchronously
  await sig.computeSignatureAsync(xml);

  const signedXml = sig.getSignedXml();
  console.log("\nSigned XML:", signedXml);

  return signedXml;
}

async function verifyXml(signedXml) {
  console.log("\n=== Verifying XML Signature with WebCrypto ===\n");

  // Load public certificate and extract the public key in SPKI format
  const certPem = readFileSync("./client_public.pem", "utf8");
  const publicKeySpki = extractPublicKeyFromCertificate(certPem);

  console.log("Note: Extracted public key from X.509 certificate");

  // Create verification object
  const sig = new SignedXml();
  sig.publicCert = publicKeySpki; // Use SPKI format public key

  // Register WebCrypto algorithms
  sig.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
  sig.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] = WebCryptoRsaSha256;

  // Verify asynchronously - checkSignatureAsync loads the signature automatically
  try {
    const isValid = await sig.checkSignatureAsync(signedXml);
    console.log("Signature is valid:", isValid);
    return isValid;
  } catch (error) {
    console.error("Signature verification failed:", error.message);
    return false;
  }
}

async function main() {
  try {
    // Sign the XML
    const signedXml = await signXml();

    // Verify the signature
    const isValid = await verifyXml(signedXml);

    if (isValid) {
      console.log("\n✅ Success! XML was signed and verified using WebCrypto API");
    } else {
      console.log("\n❌ Verification failed");
      process.exit(1);
    }
  } catch (error) {
    console.error("\n❌ Error:", error);
    process.exit(1);
  }
}

// Run the example
main();
