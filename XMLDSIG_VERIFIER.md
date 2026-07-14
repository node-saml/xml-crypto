# XmlDSigVerifier Usage Guide

`XmlDSigVerifier` provides a focused, secure, and easy-to-use API for verifying XML signatures. It is designed to replace direct usage of `SignedXml` for verification scenarios, offering built-in security checks and a simplified configuration.

## Features

- **Type-Safe Configuration:** Explicit options for different key retrieval strategies (Public Certificate, KeyInfo, Shared Secret).
- **Enhanced Security:** Built-in checks for certificate expiration, truststore validation, and limits on transform complexity.
- **Algorithm Allow-Lists:** Restrict which signature, hash, transform, and canonicalization algorithms are accepted.
- **Flexible Error Handling:** Choose between throwing errors or returning a result object.
- **Reusable Instances:** Create a verifier once and use it to verify multiple documents.
- **Two Trust Modes:** A strict path (`verifySignature`) that requires a truststore whenever the certificate is extracted from the document (`getCertFromKeyInfo`), and a deferred-trust path (`extractAndVerify`) for XAdES-LTV / archival flows where trust is established out-of-band.

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
  type DeferredTrustVerifierOptions,
  type DeferredTrustVerificationResult,
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

## Trust Model

`XmlDSigVerifier` exposes two verification paths with very different security
contracts. Pick one deliberately.

### Strict verification: `verifySignature`

Use when the signing identity must be authenticated at verification time (SAML
assertions, SSO responses, any flow where a verified signature implies a
trusted signer).

- The certificate extracted from `<KeyInfo>` is checked against a **required**
  `truststore`. Construction throws if `truststore` is omitted or empty when
  using `getCertFromKeyInfo`.
- Trust is **direct-trust** only: the extracted certificate must either
  - match a truststore entry by public key (cert pinning), or
  - be directly signed by a truststore entry (single-hop CA).
- Full PKIX path validation is **not** performed. Multi-hop chains
  (`root → intermediate → leaf`) are not walked. To handle a multi-hop chain
  either include every issuer on the path in the truststore, or pre-validate
  the chain with a dedicated PKIX library and pass only the validated leaf
  certificate.
- On failure, the error message includes the rejected certificate's `subject`
  and `issuer` to help operators identify which CA is missing from the
  truststore.

### Deferred-trust verification: `extractAndVerify`

Use only when trust will be established **out-of-band**: XAdES-LTV / XAdES-A
archival, EU Trusted List (TSL) qualified-signature validation services, UBL
e-invoicing with a counterparty registry, non-repudiation audit logs validated
later, etc.

- Performs cryptographic signature verification **only**.
- Does not accept a `truststore` and does not check expiration.
- Returns the extracted certificate as `untrustedCertificate` on success. The
  caller MUST validate that certificate against some external trust source
  before treating the signed content as authentic.

**Security warning:** a passing `extractAndVerify` result with no follow-up
trust check provides **no security guarantee**. An attacker who can supply the
document can sign it with their own keypair and the math will still verify.

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

When the XML document contains the certificate in a `<KeyInfo>` element, the
verifier extracts it and checks it against your truststore. The `truststore`
option is **required** in this mode (see [Trust Model](#trust-model)).

```typescript
import { XmlDSigVerifier, SignedXml } from "xml-crypto";
import * as fs from "fs";

const xml = fs.readFileSync("signed_with_keyinfo.xml", "utf-8");
const trustedCert = fs.readFileSync("trusted_ca.pem", "utf-8");

const result = XmlDSigVerifier.verifySignature(xml, {
  keySelector: {
    // Extract the certificate from KeyInfo
    getCertFromKeyInfo: (keyInfo) => SignedXml.getCertFromKeyInfo(keyInfo),
  },
  security: {
    // REQUIRED: the extracted certificate must match an entry here, or be
    // directly signed by an entry here. Direct trust only, no PKIX chain
    // walking; include intermediates if your chain has more than one hop.
    truststore: [trustedCert],
    // Automatically check NotBefore / NotAfter on the extracted certificate.
    checkCertExpiration: true,
  },
});

if (result.success) {
  console.log("Signature is valid and trusted.");
  // The accepted certificate is also surfaced for logging / auditing.
  console.log("Signed by:", result.certificate?.subject);
} else {
  console.log("Verification failed:", result.error);
}
```

Omitting `truststore`, or passing `truststore: []`, throws at construction
time. Empty arrays are not a supported way to bypass trust validation; if you
want signature math without trust, use
[`extractAndVerify`](#4-deferred-trust-verification-extractandverify) instead.

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

Note: When using `sharedSecretKey`, only HMAC signature algorithms are accepted — passing an asymmetric algorithm in `security.signatureAlgorithms` throws at construction. Conversely, the `publicCert` and `getCertFromKeyInfo` selectors reject HMAC algorithms. This prevents key confusion attacks.

### 4. Deferred-trust Verification (`extractAndVerify`)

For XAdES-LTV, EU TSL validation, e-invoicing archival, and similar flows
where trust is established by an external authority after signature
verification. The method performs the cryptographic check and returns the
embedded certificate **without** consulting a truststore. The result names the
field `untrustedCertificate` so the trust gap is visible at every call site.

> **Security warning.** A passing result here means only that the math
> verifies against the certificate the document claims to be signed with. It
> does NOT mean the signer is authenticated. If you forget the follow-up
> trust check, an attacker who controls the document can replace the
> certificate and signature together and your application will believe it.

```typescript
import { XmlDSigVerifier, SignedXml } from "xml-crypto";

const result = XmlDSigVerifier.extractAndVerify(xml, {
  keySelector: {
    getCertFromKeyInfo: (keyInfo) => SignedXml.getCertFromKeyInfo(keyInfo),
  },
});

if (!result.success) {
  throw new Error(`Signature math failed: ${result.error}`);
}

// result.signatureValid === true, but no trust has been established yet.
// The certificate is surfaced as result.untrustedCertificate to make the
// pending trust decision explicit — nothing enforces that you validate it.
// Treat result.signedReferences as untrusted until you do.

const isTrusted = await myTrustedListClient.isQualifiedCertificate(result.untrustedCertificate);
if (!isTrusted) {
  throw new Error("Signature is mathematically valid but the signer is not trusted.");
}

// Only now is it safe to treat result.signedReferences as authentic.
processSignedDocument(result.signedReferences);
```

Notes:

- The method is **static-only**; there is no `new XmlDSigVerifier(...).extractAndVerify(...)`. This keeps the deferred path easy to grep for in security review.
- `security.truststore` and `security.checkCertExpiration` are **not** accepted in `DeferredTrustVerifierOptions` — the types exclude them and passing them anyway fails at runtime rather than being silently ignored. If you need either, use the strict `verifySignature` path.
- `throwOnError` works the same as on `verifySignature`.

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
    // Note: the implicit canonicalization appended when a reference's transform
    // list is empty or ends with enveloped-signature counts toward the limit.
    signatureAlgorithms?: ReadonlyArray<new () => SignatureAlgorithm>; // Allowed signature algorithms
    hashAlgorithms?: ReadonlyArray<new () => HashAlgorithm>; // Allowed hash algorithms
    transformAlgorithms?: ReadonlyArray<new () => TransformAlgorithm>; // Allowed transform algorithms
    canonicalizationAlgorithms?: ReadonlyArray<new () => CanonicalizationAlgorithm>; // Allowed canonicalization algorithms

    // KeyInfo-only options (only valid with getCertFromKeyInfo selector):
    checkCertExpiration?: boolean; // Check NotBefore/NotAfter. Default: true
    truststore?: Array<string | Buffer | X509Certificate>; // REQUIRED non-empty; direct-trust anchors.
  };
}
```

When using `getCertFromKeyInfo`, `truststore` is required and must contain at
least one entry. Omitting it or passing `truststore: []` throws at construction
time. See [Trust Model](#trust-model) for the direct-trust contract.

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

#### `verifySignature` — `XmlDsigVerificationResult`

A discriminated union:

```typescript
// On success
{
  success: true,
  signedReferences: string[],          // Canonicalized XML content that was signed
  certificate?: X509Certificate        // The accepted signing cert (KeyInfo path only)
}

// On failure (when throwOnError is false)
{
  success: false,
  error: string                        // Description of what went wrong
}
```

The optional `certificate` field is populated on the `getCertFromKeyInfo` path
after the truststore check passes. It is `undefined` for the `publicCert` and
`sharedSecretKey` paths.

#### `extractAndVerify` — `DeferredTrustVerificationResult`

Structurally distinct from `XmlDsigVerificationResult`. The success branch
exposes `untrustedCertificate`, not `certificate`, because trust has NOT been
established:

```typescript
// On success: signature math verified, but the certificate is NOT trusted yet
{
  success: true,
  signatureValid: true,
  untrustedCertificate: X509Certificate,  // Validate this against a trust source!
  signedReferences: string[]
}

// On failure (when throwOnError is false)
{
  success: false,
  signatureValid: false,
  error: string
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
