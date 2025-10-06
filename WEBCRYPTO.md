# WebCrypto Support

This library now supports the Web Crypto API, which allows it to run in browsers and modern Node.js environments **without any Node.js-specific dependencies** for cryptographic operations.

## Overview

The WebCrypto implementation provides:

- **Browser compatibility**: Run XML signing and verification in the browser
- **No Node.js crypto dependency**: Uses the standard Web Crypto API
- **Async-first design**: All WebCrypto operations are asynchronous
- **Same API structure**: Follows the same patterns as the Node.js crypto implementations

## Supported Algorithms

### Hash Algorithms

- `WebCryptoSha1` - SHA-1 hashing
- `WebCryptoSha256` - SHA-256 hashing
- `WebCryptoSha512` - SHA-512 hashing

### Signature Algorithms

- `WebCryptoRsaSha1` - RSA-SHA1 signing/verification
- `WebCryptoRsaSha256` - RSA-SHA256 signing/verification
- `WebCryptoRsaSha512` - RSA-SHA512 signing/verification
- `WebCryptoHmacSha1` - HMAC-SHA1 signing/verification

## Usage

### Basic Example (Browser or Node.js with WebCrypto)

```javascript
import { SignedXml, WebCryptoRsaSha256, WebCryptoSha256 } from "xml-crypto";

// Your XML to sign
const xml = "<root><data>Hello World</data></root>";

// Your private key (PEM format)
const privateKey = `-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----`;

// Create SignedXml instance
const sig = new SignedXml();

// Use WebCrypto algorithms
sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
sig.privateKey = privateKey;

// Add reference with WebCrypto hash algorithm
sig.addReference({
  xpath: "//*[local-name(.)='data']",
  digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
});

// Register WebCrypto algorithms
sig.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
sig.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] = WebCryptoRsaSha256;

// Compute signature asynchronously
const signedXml = await sig.computeSignatureAsync(xml);

console.log(signedXml.getSignedXml());
```

### Verifying a Signature

```javascript
import { SignedXml, WebCryptoRsaSha256, WebCryptoSha256 } from "xml-crypto";

const signedXml = `<root>...</root>`; // Your signed XML

const sig = new SignedXml();

// Register WebCrypto algorithms
sig.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
sig.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] = WebCryptoRsaSha256;

// Provide public key or certificate
sig.publicCert = publicKey;

// Load the signature
sig.loadSignature(signedXml);

// Verify asynchronously
try {
  const isValid = await sig.checkSignatureAsync(signedXml);
  console.log("Signature valid:", isValid);
} catch (error) {
  console.error("Signature verification failed:", error);
}
```

## Key Format Conversion

The WebCrypto algorithms accept keys in PEM format (strings) and will automatically convert them to `CryptoKey` objects. You can also pre-import keys using the utility functions:

```javascript
import { importRsaPrivateKey, importRsaPublicKey } from "xml-crypto";

// Import private key for signing
const privateKey = await importRsaPrivateKey(pemPrivateKey, "SHA-256");

// Import public key for verification
const publicKey = await importRsaPublicKey(pemPublicKey, "SHA-256");

// Use with SignedXml
const sig = new SignedXml();
sig.privateKey = privateKey; // Can use CryptoKey directly
```

## Async vs Sync Methods

### Async Methods (for WebCrypto)

- `computeSignatureAsync(xml, options?)` - Computes signature asynchronously
- `checkSignatureAsync(xml)` - Verifies signature asynchronously

### Sync Methods (for Node.js crypto)

- `computeSignature(xml, options?, callback?)` - Computes signature synchronously (or with callback)
- `checkSignature(xml, callback?)` - Verifies signature synchronously (or with callback)

**Important**: You must use the async methods (`*Async`) when using WebCrypto algorithms. The sync methods will throw an error if you try to use them with WebCrypto algorithms.

## Browser Compatibility

The WebCrypto API is supported in all modern browsers:

- Chrome/Edge 37+
- Firefox 34+
- Safari 11+

## Node.js Compatibility

WebCrypto is available in Node.js 15.0.0+ via the global `crypto.subtle` object. For older Node.js versions, continue using the standard crypto-based algorithms.

## Migration from Node.js Crypto

To migrate from Node.js crypto to WebCrypto:

1. Change algorithm imports:

   ```javascript
   // Before
   import { Sha256, RsaSha256 } from "xml-crypto";

   // After
   import { WebCryptoSha256, WebCryptoRsaSha256 } from "xml-crypto";
   ```

2. Update method calls to async:

   ```javascript
   // Before
   sig.computeSignature(xml);

   // After
   await sig.computeSignatureAsync(xml);
   ```

3. Register algorithms:
   ```javascript
   sig.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
   sig.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] =
     WebCryptoRsaSha256;
   ```

## Limitations

1. **X.509 Certificates**: The Web Crypto API doesn't directly support X.509 certificates. If you have a certificate, you need to extract the public key in SPKI format first:

   ```javascript
   // In Node.js, you can extract it like this:
   import { createPublicKey } from "crypto";

   const publicKey = createPublicKey(certificatePem);
   const spkiPublicKey = publicKey.export({
     type: "spki",
     format: "pem",
   });

   // Use spkiPublicKey with WebCrypto algorithms
   sig.publicCert = spkiPublicKey;
   ```

   In browsers, you'll need to prepare the keys in SPKI format beforehand or use a library to parse X.509 certificates.

2. **PEM/DER parsing**: The utility functions provide basic PEM parsing.
3. **Key formats**: Only PKCS8 private keys and SPKI public keys are currently supported for RSA.
4. **Async requirement**: All WebCrypto operations are async - you cannot use them with the synchronous API methods.

## Benefits

- **Zero dependencies on Node.js crypto**: Run in any environment that supports Web Crypto API
- **Browser support**: Enable XML signing/verification in web applications
- **Standard API**: Uses the widely-supported Web Crypto API standard
- **Future-proof**: Web Crypto is the modern standard for cryptography on the web

## Example: Complete Sign and Verify Flow

```javascript
import { SignedXml, WebCryptoRsaSha256, WebCryptoSha256 } from "xml-crypto";

async function signAndVerify() {
  const xml = "<root><data>Important data</data></root>";

  // Signing
  const sigForSigning = new SignedXml();
  sigForSigning.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  sigForSigning.privateKey = privateKeyPem;
  sigForSigning.addReference({
    xpath: "//*[local-name(.)='data']",
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
  });

  // Register algorithms
  sigForSigning.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
  sigForSigning.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] =
    WebCryptoRsaSha256;

  await sigForSigning.computeSignatureAsync(xml);
  const signedXml = sigForSigning.getSignedXml();

  // Verification
  const sigForVerifying = new SignedXml();
  sigForVerifying.publicCert = publicKeyPem;

  // Register algorithms for verification
  sigForVerifying.HashAlgorithms["http://www.w3.org/2001/04/xmlenc#sha256"] = WebCryptoSha256;
  sigForVerifying.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] =
    WebCryptoRsaSha256;

  sigForVerifying.loadSignature(signedXml);

  const isValid = await sigForVerifying.checkSignatureAsync(signedXml);
  console.log("Signature is valid:", isValid);

  return isValid;
}

signAndVerify().catch(console.error);
```
