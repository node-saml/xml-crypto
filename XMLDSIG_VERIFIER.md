# XmlDSigVerifier Usage Guide

`XmlDSigVerifier` provides a focused, secure, and easy-to-use API for verifying XML signatures. It is designed to replace direct usage of `SignedXml` for verification scenarios, offering built-in security checks and a simplified configuration.

## Features

- **Type-Safe Configuration:** Explicit options for different key retrieval strategies (Public Certificate, KeyInfo, Shared Secret).
- **Enhanced Security:** Built-in checks for certificate expiration, truststore validation, and limits on transform complexity.
- **Algorithm Allow-Lists:** Restrict which signature, hash, transform, and canonicalization algorithms are accepted.
- **Flexible Error Handling:** Choose between throwing errors or returning a result object.
- **Reusable Instances:** Create a verifier once and use it to verify multiple documents.

## Installation

Ensure you have `xml-crypto` installed:

```bash
npm install xml-crypto
```

## Imports

```typescript
import {
  XmlDSigVerifier,
  XMLDSIG_URIS,
  // Algorithm classes (for customizing allowed algorithms)
  Sha1,
  Sha256,
  Sha512,
  RsaSha1,
  RsaSha256,
  RsaSha256Mgf1,
  RsaSha512,
  HmacSha1,
  EnvelopedSignature,
  C14nCanonicalization,
  C14nCanonicalizationWithComments,
  ExclusiveCanonicalization,
  ExclusiveCanonicalizationWithComments,
  // Types (optional, for TypeScript users)
  type XmlDSigVerifierOptions,
  type XmlDsigVerificationResult,
} from "xml-crypto";
```

`XMLDSIG_URIS` provides constants for all supported algorithm URIs:

```typescript
XMLDSIG_URIS.SIGNATURE_ALGORITHMS.RSA_SHA256; // "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
XMLDSIG_URIS.HASH_ALGORITHMS.SHA256; // "http://www.w3.org/2001/04/xmlenc#sha256"
XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N; // "http://www.w3.org/2001/10/xml-exc-c14n#"
XMLDSIG_URIS.TRANSFORM_ALGORITHMS.ENVELOPED_SIGNATURE; // "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
XMLDSIG_URIS.NAMESPACES.ds; // "http://www.w3.org/2000/09/xmldsig#"
```

## Quick Start

### 1. Verifying with a Public Certificate

If you already have the public certificate or key and want to verify a document signed with the corresponding private key:

```typescript
import { XmlDSigVerifier } from "xml-crypto";
import * as fs from "fs";

const xml = fs.readFileSync("signed_document.xml", "utf-8");
const publicCert = fs.readFileSync("public_key.pem", "utf-8");

const result = XmlDSigVerifier.verifySignature(xml, {
  keySelector: { publicCert: publicCert },
});

if (result.success) {
  console.log("Signature valid!");
  // Access the signed content securely
  console.log("Signed references:", result.signedReferences);
} else {
  console.error("Verification failed:", result.error);
}
```

### 2. Verifying using KeyInfo (with Truststore)

When the XML document contains the certificate in a `<KeyInfo>` element, you can verify it while ensuring the certificate is trusted and valid.

```typescript
import { XmlDSigVerifier, SignedXml } from "xml-crypto";
import * as fs from "fs";

const xml = fs.readFileSync("signed_with_keyinfo.xml", "utf-8");
const trustedRootCert = fs.readFileSync("root_ca.pem", "utf-8");

const result = XmlDSigVerifier.verifySignature(xml, {
  keySelector: {
    // Extract the certificate from KeyInfo
    getCertFromKeyInfo: (keyInfo) => SignedXml.getCertFromKeyInfo(keyInfo),
  },
  security: {
    // Ensure the certificate is trusted by your root CA
    truststore: [trustedRootCert],
    // Automatically check if the certificate is expired
    checkCertExpiration: true,
  },
});

if (result.success) {
  console.log("Signature is valid and trusted.");
} else {
  console.log("Verification failed:", result.error);
}
```

### 3. Verifying with a Shared Secret (HMAC)

For documents signed with HMAC (symmetric key):

```typescript
import { XmlDSigVerifier } from "xml-crypto";

const result = XmlDSigVerifier.verifySignature(xml, {
  keySelector: { sharedSecretKey: "my-shared-secret" },
});

if (result.success) {
  console.log("HMAC signature valid!");
}
```

Note: When using `sharedSecretKey`, HMAC signature algorithms are enabled and asymmetric algorithms are disabled by default to prevent key confusion attacks.

## Advanced Usage

### Reusing the Verifier Instance

For better performance when verifying multiple documents with the same configuration, create an instance of `XmlDSigVerifier`:

```typescript
const verifier = new XmlDSigVerifier({
  keySelector: { publicCert: myPublicCert },
  security: { maxTransforms: 2 },
});

const result1 = verifier.verifySignature(xml1);
const result2 = verifier.verifySignature(xml2);
```

### Verification Options

The `verifySignature` method accepts an options object with the following structure:

```typescript
interface XmlDSigVerifierOptions {
  // STRATEGY: Choose one of the following key selectors
  keySelector:
    | { publicCert: KeyLike } // Direct public key/cert
    | { getCertFromKeyInfo: (node?: Node | null) => string | null } // Extract certificate from XML
    | { sharedSecretKey: KeyLike }; // HMAC shared secret

  // CONFIGURATION
  idAttributes?: VerificationIdAttributeType[]; // Default: ["Id", "ID", "id"]
  implicitTransforms?: ReadonlyArray<TransformAlgorithmURI>; // Hidden transforms to apply
  throwOnError?: boolean; // Default: false (returns result object)

  // SECURITY
  security?: {
    maxTransforms?: number; // Limit transforms per reference (DoS protection). Default: 4
    signatureAlgorithms?: Array<new () => SignatureAlgorithm>; // Allowed signature algorithms
    hashAlgorithms?: Array<new () => HashAlgorithm>; // Allowed hash algorithms
    transformAlgorithms?: Array<new () => TransformAlgorithm>; // Allowed transform algorithms
    canonicalizationAlgorithms?: Array<new () => CanonicalizationAlgorithm>; // Allowed canonicalization algorithms

    // KeyInfo-only options (only available with getCertFromKeyInfo selector):
    checkCertExpiration?: boolean; // Check NotBefore/NotAfter. Default: true
    truststore?: Array<string | Buffer | X509Certificate>; // Trusted CA certificates
  };
}
```

#### Extending Defaults with Custom Algorithms

Algorithm lists are simple arrays of constructor classes. Each class provides its own URI via `getAlgorithmName()`, eliminating the need for manual URI keys. To add a custom algorithm alongside the defaults, spread the default array:

```typescript
import { XmlDSigVerifier } from "xml-crypto";
import { MyCustomHashAlgorithm } from "./my-algorithms";

const result = XmlDSigVerifier.verifySignature(xml, {
  keySelector: { publicCert },
  security: {
    hashAlgorithms: [...XmlDSigVerifier.defaultHashAlgorithms, MyCustomHashAlgorithm],
  },
});
```

### ID Attributes

The `idAttributes` option controls which XML attributes are treated as element identifiers when resolving signature references.

```typescript
// Simple string format (matches attribute name in any namespace)
idAttributes: ["Id", "ID", "customId"];

// Namespaced format for stricter matching
idAttributes: [
  { localName: "Id", namespaceUri: "http://example.com/ns" }, // Match only in specific namespace
  { localName: "Id", namespaceUri: null }, // Match only non-namespaced attributes
  { localName: "Id" }, // Match regardless of namespace (same as string)
];
```

### Implicit Transforms

If you fail to verify signed XML, one possible cause is hidden implicit transforms that were applied during signing but not listed in the signature. Use `implicitTransforms` to specify them:

```typescript
const result = XmlDSigVerifier.verifySignature(xml, {
  keySelector: { publicCert },
  implicitTransforms: [XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.C14N],
});
```

### Error Handling

By default, `verifySignature` returns a result object. If you prefer to handle exceptions:

```typescript
try {
  const result = XmlDSigVerifier.verifySignature(xml, {
    keySelector: { publicCert },
    throwOnError: true, // Will throw Error on failure
  });
  // If code reaches here, signature is valid
} catch (e) {
  console.error("Signature invalid:", e.message);
}
```

### Result Types

The verification result is a discriminated union:

```typescript
// On success
{
  success: true,
  signedReferences: string[]  // Canonicalized XML content that was signed
}

// On failure (when throwOnError is false)
{
  success: false,
  error: string  // Description of what went wrong
}
```

### Handling Multiple Signatures

If a document contains multiple signatures, you must specify which one to verify by passing the signature node.

```typescript
import { DOMParser } from "@xmldom/xmldom";

const doc = new DOMParser().parseFromString(xml, "application/xml");
const signatures = doc.getElementsByTagNameNS(XMLDSIG_URIS.NAMESPACES.ds, "Signature");

// Verify the second signature
const result = XmlDSigVerifier.verifySignature(
  xml,
  {
    keySelector: { publicCert },
  },
  signatures[1],
);
```
