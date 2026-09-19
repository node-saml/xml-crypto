# xml-crypto

![Build Status](https://github.com/node-saml/xml-crypto/workflows/Test%20Status/badge.svg)
[![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)
[![codecov](https://codecov.io/gh/node-saml/xml-crypto/branch/master/graph/badge.svg?token=PQWCMBWBFB)](https://codecov.io/gh/node-saml/xml-crypto)
[![DeepScan grade](https://deepscan.io/api/teams/17569/projects/30525/branches/981134/badge/grade.svg)](https://deepscan.io/dashboard#view=project&tid=17569&pid=30525&bid=981134)

[![NPM](https://nodei.co/npm/xml-crypto.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/xml-crypto)

## Sponsors

![workos](https://github.com/workos.png?size=30) [workos](https://github.com/workos)

## Upgrading

### Canonicalization output

Inclusive canonicalization (`http://www.w3.org/TR/2001/REC-xml-c14n-20010315` and its
`#WithComments` variant) renders namespace declarations as the
[C14N specification](https://www.w3.org/TR/2001/REC-xml-c14n-20010315#ProcessingModel) requires,
including when:

- a prefixed element in the signed content declares a default namespace, as in
  `<p:item xmlns="urn:x">`
- the signed element inherits a default namespace and declares a prefixed namespace of its own
- the signed element is prefixed, inherits a default namespace, and contains an element that
  clears it with `xmlns=""`
- the signed element redeclares a prefix that an ancestor binds, after declaring another namespace

Exclusive canonicalization (`http://www.w3.org/2001/10/xml-exc-c14n#` and its `#WithComments`
variant) renders the last case the same way when the redeclared prefix is listed in the
`InclusiveNamespaces` `PrefixList`.

### Comments in referenced content

A `Reference` whose `URI` is empty or `#` followed by an ID, such as `#item`, removes comments from
the referenced content before its transforms run, as
[same-document references](https://www.w3.org/TR/xmldsig-core1/#sec-Same-Document) require.

- Comments in that content are not signed, even with a `#WithComments` transform: adding, removing
  or changing one does not invalidate the signature. Read signed content from
  `getSignedReferences()`, which does not contain them.
- A custom transform in such a reference does not receive comment nodes.
- A `#WithComments` `CanonicalizationMethod` signs the comments inside `SignedInfo`.

### Transforms that end in a DOM node

When the last transform of a `Reference` returns a DOM `Node`, it is converted to octets with
inclusive canonicalization, as the
[reference processing model](https://www.w3.org/TR/xmldsig-core1/#sec-ReferenceProcessingModel)
requires. A `SignedInfo` canonicalization algorithm that returns a `Node` is converted the same way,
and `getCanonXml()` returns canonical XML for such transform lists, for example `<y></y>`.

### Transforms that follow a canonicalization

When a transform returns a string and another transform follows it in the same `Reference`, the
string is parsed into a new document and the next transform is applied to that, as the
[reference processing model](https://www.w3.org/TR/xmldsig-core1/#sec-ReferenceProcessingModel)
requires. Every built-in canonicalization algorithm returns a string, so:

- `enveloped-signature` after a canonicalization removes the `Signature`, including one inside the
  referenced element.
- The result of a `#WithComments` canonicalization followed by `enveloped-signature` is
  [canonicalized](#transforms-that-end-in-a-dom-node) without comments.
- Exclusive canonicalization after inclusive canonicalization omits inherited namespace declarations
  that the referenced element does not use.
- A custom transform after a canonicalization receives the parsed document.
- A transform throws when the string returned by the transform before it is not well-formed XML.

### Copies of an enveloped signature

The `enveloped-signature` transform removes only the `Signature` element being verified, as
[XMLDSig](https://www.w3.org/TR/xmldsig-core1/#sec-EnvelopedSignature) requires.

- `checkSignature()` finds that element by its `SignatureValue`, and throws when the document
  contains more than one `Signature` element with that value.
- `getCanonXml()` finds the loaded signature in the node's document the same way, and removes nothing
  when the signature is not there.

### Malformed certificates

A certificate whose encapsulated data is not base64 is rejected rather than decoded as far as it
goes. `Buffer.from(value, "base64")` discards what it does not recognize, so a corrupt certificate
used to reach `KeyInfo`, or Node's crypto, as whatever bytes survived that. What the parser accepts is
described under [X.509 / Key formats](#x509--key-formats).

The error for a value the parser cannot read is `Invalid PEM format.`, in place of the
`Unknown DER format.` that `derToPem()` threw. A `Buffer` holding the bytes of a PEM file is read
as that file rather than base64-encoded, which is what made it a message with a body of
base64-encoded PEM. Both forms of PEM the parser does read produce the same canonical output.

### Deprecated ahead of 7.0

These exports are deprecated and will be removed in 7.0:

| Deprecated                                                            | Instead                                                                                                                                                                                                       |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `findAttr`, `findChildren`, `findChilds`, `isDescendantOf`            | use a DOM API, or [xpath](https://github.com/goto100/xpath)                                                                                                                                                   |
| `encodeSpecialCharactersInAttribute`, `encodeSpecialCharactersInText` | these are the escaping step of `C14nCanonicalization` and `ExclusiveCanonicalization`, so use those; a custom canonicalizer must apply [C14N escaping](https://www.w3.org/TR/xml-c14n#ProcessingModel) itself |
| `isArrayHasLength`                                                    | `Array.isArray(x) && x.length > 0`                                                                                                                                                                            |
| `validateDigestValue`                                                 | decode both from base64, then compare with `a.length === b.length && crypto.timingSafeEqual(a, b)` — `timingSafeEqual` alone throws on a length mismatch instead of returning `false`. Never `===`            |
| `BASE64_REGEX`, `EXTRACT_X509_CERTS`, `PEM_FORMAT_REGEX`              | `toPem()`, `pemToDer()` and `pemCertificates()` apply the rules these described, and validate the encapsulated data as well; see [X.509 / Key formats](#x509--key-formats)                                    |
| `derToPem`                                                            | `toPem()`, which is the same function under a name that describes it: it takes a PEM message, several of them, base64, or a Buffer, and DER is only one of those                                              |

Calling one prints a `DeprecationWarning` naming its replacement. The three regexes cannot warn —
`util.deprecate` needs a call to intercept — so TypeScript users see the `@deprecated` tag and
JavaScript users get no signal until the names go away.

`toPem`, `pemToDer`, `pemCertificates`, `normalizePem` and `findAncestorNs` are **not**
deprecated and stay exported.

`getReferences()` and `references` are deprecated. Do not use them to obtain signed XML; use
`getSignedReferences()` instead, as shown in [Verifying Xml documents](#verifying-xml-documents).

## Supported Algorithms

### Canonicalization and Transformation Algorithms

- Canonicalization <http://www.w3.org/TR/2001/REC-xml-c14n-20010315>
- Canonicalization with comments <http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments>
- Exclusive Canonicalization <http://www.w3.org/2001/10/xml-exc-c14n#>
- Exclusive Canonicalization with comments <http://www.w3.org/2001/10/xml-exc-c14n#WithComments>
- Enveloped Signature transform <http://www.w3.org/2000/09/xmldsig#enveloped-signature>

### Hashing Algorithms

- SHA1 digests <http://www.w3.org/2000/09/xmldsig#sha1>
- SHA256 digests <http://www.w3.org/2001/04/xmlenc#sha256>
- SHA512 digests <http://www.w3.org/2001/04/xmlenc#sha512>

### Signature Algorithms

- RSA-SHA1 <http://www.w3.org/2000/09/xmldsig#rsa-sha1>
- RSA-SHA256 <http://www.w3.org/2001/04/xmldsig-more#rsa-sha256>
- RSA-SHA256 with MGF1 <http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1>
- RSA-SHA512 <http://www.w3.org/2001/04/xmldsig-more#rsa-sha512>

HMAC-SHA1 is also available but it is disabled by default

- HMAC-SHA1 <http://www.w3.org/2000/09/xmldsig#hmac-sha1>

to enable HMAC-SHA1, call `enableHMAC()` on your instance of `SignedXml`.

This will enable HMAC and disable digital signature algorithms. Due to key
confusion issues, it is risky to have both HMAC-based and public key digital
signature algorithms enabled at same time.

[You are able to extend xml-crypto with custom algorithms.](#customizing-algorithms)

## Signing Xml documents

When signing a xml document you can pass the following options to the `SignedXml` constructor to customize the signature process:

- `privateKey` - **[required]** a `Buffer` or pem encoded `String` containing your private key
- `publicCert` - **[optional]** the X.509 certificate to publish in `<KeyInfo>`, or a chain of them with the signing certificate first, as PEM or as one certificate's base64 without the PEM boundaries, in a `String` or `Buffer`. A value that holds no certificate, such as a public key, produces no `<KeyInfo>`.
- `signatureAlgorithm` - **[required]** one of the supported [signature algorithms](#signature-algorithms). Ex: `sign.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"`
- `canonicalizationAlgorithm` - **[required]** one of the supported [canonicalization algorithms](#canonicalization-and-transformation-algorithms). Ex: `sign.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"`

Use this code:

```javascript
const { SignedXml } = require("xml-crypto");
const fs = require("fs");

const xml = "<library><book><name>Harry Potter</name></book></library>";

const sig = new SignedXml({
  privateKey: fs.readFileSync("client.pem"),
  canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
  signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
});
sig.addReference({
  xpath: "//*[local-name(.)='book']",
  digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
});
sig.computeSignature(xml);
fs.writeFileSync("signed.xml", sig.getSignedXml());
```

The result will be:

```xml
<library>
  <book Id="_0">
    <name>Harry Potter</name>
  </book>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
      <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
      <Reference URI="#_0">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
        <DigestValue>9d/ciWlVZkaJnJ3KBB5WY1H2Y8WRXPB2DquM0goT8jY=</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>uxmxGw2O3B6ylkhEXOaZ...[long base64 removed]...</SignatureValue>
  </Signature>
</library>
```

Note:

If `publicCert` contains an X.509 certificate, the default `SignedXml.getKeyInfoContent` includes it in a `<KeyInfo>` element:

```xml
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo>
    ...[signature info removed]...
  </SignedInfo>
  <SignatureValue>uxmxGw2O3B6ylkhEXOaZ...[long base64 removed]...</SignatureValue>
  <KeyInfo>
    <X509Data>
      <X509Certificate>MIIGYjCCBJagACCBN...[long base64 removed]...</X509Certificate>
    </X509Data>
  </KeyInfo>
</Signature>
```

To customize this see [customizing algorithms](#customizing-algorithms) for an example.

## Verifying Xml documents

When verifying a xml document you can pass the following options to the `SignedXml` constructor to customize the verify process:

- `publicCert` - **[optional]** your certificate as a string, a string of multiple certs in PEM format, or a Buffer
- `privateKey` - **[optional]** your private key as a string or a Buffer - used for verifying symmetrical signatures (HMAC)

The certificate that will be used to check the signature will first be determined by calling `this.getCertFromKeyInfo()`, which function you can customize as you see fit. If that returns `null`, then `publicCert` is used. If that is `null`, then `privateKey` is used (for symmetrical signing applications).

Example:

```javascript
new SignedXml({
  publicCert: client_public_pem,
  getCertFromKeyInfo: () => null,
});
```

You can use any dom parser you want in your code (or none, depending on your usage). This sample uses [xmldom](https://github.com/xmldom/xmldom) and [xpath](https://github.com/goto100/xpath), so you should install them first:

```shell
npm install @xmldom/xmldom xpath
```

Example:

```javascript
const { DOMParser } = require("@xmldom/xmldom");
const xpath = require("xpath");
const { SignedXml } = require("xml-crypto");
const fs = require("fs");

const xml = fs.readFileSync("signed.xml", "utf8");
const doc = new DOMParser().parseFromString(xml, "text/xml");

// DO NOT attempt to parse whatever data object you have here in `doc`
// and then use it to verify the signature. This can lead to security issues.
// i.e. BAD: parseAssertion(doc),
// good: see below

const signature = xpath.select1(
  "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
  doc,
);
const sig = new SignedXml({ publicCert: fs.readFileSync("client_public.pem") });
sig.loadSignature(signature);
const res = sig.checkSignature(xml);
```

In order to protect from some attacks we must check the content we want to use is the one that has been signed:

```javascript
if (!res) {
  throw new Error("Invalid signature");
}
// good: The XML Signature has been verified, meaning some subset of XML is verified.
const signedBytes = sig.getSignedReferences();

const authenticatedDoc = new DOMParser().parseFromString(signedBytes[0], "text/xml"); // Take the first signed reference
// It is now safe to load SAML, obtain the assertion XML, or do whatever else is needed.
// Be sure to only use authenticated data.
const signedAssertionNode = extractAssertion(authenticatedDoc);
const parsedAssertion = parseAssertion(signedAssertionNode);

return parsedAssertion; // This the correctly verified signed Assertion

// BAD example: DO not use the .getReferences() API.
```

Note:

The xml-crypto api requires you to supply it separately the xml signature ("&lt;Signature&gt;...&lt;/Signature&gt;", in loadSignature) and the signed xml (in checkSignature). The signed xml may or may not contain the signature in it, but you are still required to supply the signature separately.

### Caring for Implicit transform

If you fail to verify signed XML, then one possible cause is that there are some hidden implicit transforms(#).  
(#) Normalizing XML document to be verified. i.e. remove extra space within a tag, sorting attributes, importing namespace declared in ancestor nodes, etc.

The reason for these implicit transform might come from [complex xml signature specification](https://www.w3.org/TR/2002/REC-xmldsig-core-20020212),
which makes XML developers confused and then leads to incorrect implementation for signing XML document.

If you keep failing verification, it is worth trying to guess such a hidden transform and specify it to the option as below:

```javascript
const sig = new SignedXml({
  implicitTransforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
  publicCert: fs.readFileSync("client_public.pem"),
});
sig.loadSignature(signature);
const res = sig.checkSignature(xml);
```

Implicit transforms run after the transforms a `<Reference>` declares. xml-crypto converts a
node-set left after the last transform to octets with Canonical XML 1.0, so an implicit
`http://www.w3.org/TR/2001/REC-xml-c14n-20010315` changes nothing where the transforms end in a
node-set, such as when there are none or the last one is enveloped-signature.

You might find it difficult to guess such transforms, but there are typical transforms you can try.

- <http://www.w3.org/TR/2001/REC-xml-c14n-20010315>
- <http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments>
- <http://www.w3.org/2001/10/xml-exc-c14n#>
- <http://www.w3.org/2001/10/xml-exc-c14n#WithComments>

## API

### SignedXml

The `SignedXml` constructor provides an abstraction for sign and verify xml documents. The object is constructed using `new SignedXml(options?: SignedXmlOptions)` where the possible options are:

- `idMode` - default `null` - if the value of `wssecurity` is passed it will create/validate id's with the ws-security namespace.
- `idAttribute` - string - default `undefined` - the name of an additional attribute that holds an element's id; it is checked before `Id`, `ID` and `id`
- `privateKey` - string or Buffer - default `null` - the private key to use for signing
- `publicCert` - string or Buffer - default `null` - the public certificate to use for verifying
- `signatureAlgorithm` - string - the signature algorithm to use
- `canonicalizationAlgorithm` - string - default `undefined` - the canonicalization algorithm to use
- `inclusiveNamespacesPrefixList` - string - default `null` - a list of namespace prefixes to include during canonicalization
- `implicitTransforms` - string[] - default `[]` - a list of implicit transforms to use during verification
- `keyInfoAttributes` - object - default `{}` - a hash of attributes and values `attrName: value` to add to the KeyInfo node
- `getKeyInfoContent` - function - default `SignedXml.getKeyInfoContent` - a function that returns the content of the KeyInfo node
- `getCertFromKeyInfo` - function - default `noop` - a function that returns the certificate from the `<KeyInfo />` node

#### API

A `SignedXml` object provides the following methods:

To sign xml documents:

- `addReference({ xpath, transforms, digestAlgorithm, id, type })` - adds a reference to a xml element where:
  - `xpath` - a string containing a XPath expression referencing a xml element
  - `transforms` - an array of [transform algorithms](#canonicalization-and-transformation-algorithms), the referenced element will be transformed for each value in the array
  - `digestAlgorithm` - one of the supported [hashing algorithms](#hashing-algorithms)
  - `id` - an optional `Id` attribute to add to the reference element
  - `type` - the optional `Type` attribute to add to the reference element (represented as a URI)
- `computeSignature(xml, [options])` - compute the signature of the given xml where:
  - `xml` - a string containing a xml document
  - `options` - an object with the following properties:
    - `prefix` - adds this value as a prefix for the generated signature tags
    - `attrs` - a hash of attributes and values `attrName: value` to add to the signature root node
    - `location` - customize the location of the signature, pass an object with a `reference` key which should contain a XPath expression to a reference node, an `action` key which should contain one of the following values: `append`, `prepend`, `before`, `after`
    - `existingPrefixes` - A hash of prefixes and namespaces `prefix: namespace` that shouldn't be in the signature because they already exist in the xml
- `getSignedXml()` - returns the original xml document with the signature in it, **must be called only after `computeSignature`**
- `getSignatureXml()` - returns just the signature part, **must be called only after `computeSignature`**
- `getOriginalXmlWithIds()` - **[deprecated]** returns the original xml with Id attributes added on relevant elements, **must be called only after `computeSignature`**. Use the `location` option of `computeSignature()` to place the signature, then `getSignedXml()`. See [how to specify the location of the signature](#how-to-specify-the-location-of-the-signature). For a detached signature, put an ID attribute the signer recognizes on each referenced element (`wsu:Id` for WS-Security), sign that document, and send it alongside `getSignatureXml()`. Make sure each reference XPath still selects its intended element once those IDs are present, for example by selecting on the ID itself.

Every reference XPath is evaluated against the input document before any IDs or the signature
are added, so the order of `addReference()` calls does not change what a reference selects. A
reference that matches nothing in the input is evaluated after the signature is inserted and
selects only elements inside the new signature, such as generated `Object` or `KeyInfo`
elements. Use separate `addReference()` calls for input elements and generated signature content.

An input match takes precedence, so a reference whose XPath also matches an input element signs
that element and leaves the generated one unsigned. Select generated content by the `Id` you
configured for it, as in [how to add custom Objects to the signature](#how-to-add-custom-objects-to-the-signature),
rather than by element name.

To verify xml documents:

- `loadSignature(signatureXml)` - loads the signature where:
  - `signatureXml` - a string or node object (like an [xmldom](https://github.com/xmldom/xmldom) node) containing the xml representation of the signature
- `checkSignature(xml)` - validates the given xml document and returns `true` if the validation was successful
- `getSignedReferences()` - returns the canonical XML of each reference, only after `checkSignature` succeeds
- `validateElementAgainstReferences(elemOrXpath, doc)` - **[deprecated]** after `checkSignature` succeeds, use the XML that `getSignedReferences()` returns instead of nodes from the original document

## Customizing Algorithms

The following sample shows how to sign a message using custom algorithms.

First import some modules:

```javascript
const { SignedXml } = require("xml-crypto");
const fs = require("fs");
```

Now define the extension point you want to implement. You can choose one or more.

To determine the inclusion and contents of a `<KeyInfo />` element, the function
`this.getKeyInfoContent()` is called. There is a default implementation of this. If you wish to change
this implementation, provide your own function assigned to the property `this.getKeyInfoContent`. If
it returns no content, the `<KeyInfo />` element is not included in the generated XML, even when
`keyInfoAttributes` are set.

To specify custom attributes on `<KeyInfo />`, add the properties to the `.keyInfoAttributes` property.

A custom hash algorithm is used to calculate digests. Implement it if you want a hash other than the built-in methods.

```javascript
class MyDigest {
  getHash(xml) {
    return "the base64 hash representation of the given xml string";
  }

  getAlgorithmName() {
    return "http://myDigestAlgorithm";
  }
}
```

A custom signing algorithm.

```javascript
class MySignatureAlgorithm {
  // Sign the given SignedInfo using the key. Return the base64 signature value.
  getSignature(signedInfo, privateKey) {
    return "signature of signedInfo as base64...";
  }

  getAlgorithmName() {
    return "http://mySigningAlgorithm";
  }
}
```

Custom transformation algorithm.

```javascript
class MyTransformation {
  // Given a node (from the xmldom module), return its canonical representation as a string.
  process(node) {
    // You should apply your transformation before returning.
    return node.toString();
  }

  getAlgorithmName() {
    return "http://myTransformation";
  }
}
```

Custom canonicalization is actually the same as custom transformation. It is applied on the SignedInfo rather than on references.

```javascript
class MyCanonicalization {
  // Given a node (from the xmldom module), return its canonical representation as a string.
  process(node) {
    // You should apply your canonicalization before returning.
    return node.toString();
  }

  getAlgorithmName() {
    return "http://myCanonicalization";
  }
}
```

Now register the new algorithms on a `SignedXml` instance, under the names their `getAlgorithmName()`
returns, and configure the instance to use them:

```javascript
function signXml(xml, xpath, key, dest) {
  const sig = new SignedXml({
    publicCert: fs.readFileSync("my_public_cert.pem", "latin1"),
    privateKey: fs.readFileSync(key),
    // Configure the signature object to use the custom algorithms.
    signatureAlgorithm: "http://mySigningAlgorithm",
    canonicalizationAlgorithm: "http://myCanonicalization",
  });

  // Register all the custom algorithms.
  sig.CanonicalizationAlgorithms["http://myTransformation"] = MyTransformation;
  sig.CanonicalizationAlgorithms["http://myCanonicalization"] = MyCanonicalization;
  sig.HashAlgorithms["http://myDigestAlgorithm"] = MyDigest;
  sig.SignatureAlgorithms["http://mySigningAlgorithm"] = MySignatureAlgorithm;

  sig.addReference({
    xpath,
    transforms: ["http://myTransformation"],
    digestAlgorithm: "http://myDigestAlgorithm",
  });
  sig.computeSignature(xml);
  fs.writeFileSync(dest, sig.getSignedXml());
}

const xml = "<library><book><name>Harry Potter</name></book></library>";

signXml(xml, "//*[local-name(.)='book']", "client.pem", "result.xml");
```

You can always look at the actual code as a sample.

## Asynchronous signing

If the private key is not stored locally, and you wish to use a signing server or Hardware Security Module (HSM) to sign documents, you can create a custom signing algorithm that uses an asynchronous callback. Register it under the URI of the algorithm it implements, which is the `SignatureMethod` a verifier reads.

```javascript
const { SignedXml } = require("xml-crypto");
const crypto = require("crypto");
const fs = require("fs");

class AsyncRsaSha256 {
  getSignature(signedInfo, privateKey, callback) {
    // Do some asynchronous things here, such as calling a signing server.
    const signer = crypto.createSign("RSA-SHA256");
    signer.update(signedInfo);
    callback(null, signer.sign(privateKey, "base64"));
  }

  getAlgorithmName() {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  }
}

const xml = "<library><book><name>Harry Potter</name></book></library>";

const sig = new SignedXml({
  privateKey: fs.readFileSync("client.pem"),
  canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
  signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
});
sig.SignatureAlgorithms["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] = AsyncRsaSha256;
sig.addReference({
  xpath: "//*[local-name(.)='book']",
  digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
});
sig.computeSignature(xml, (err) => {
  if (err) {
    console.error(err);
    return;
  }
  fs.writeFileSync("signed.xml", sig.getSignedXml());
});
```

## X.509 / Key formats

Xml-Crypto internally relies on node's crypto module. This means pem encoded certificates are supported. So to sign an xml use key.pem that looks like this (only the beginning of the key content is shown):

```text
-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0...
-----END PRIVATE KEY-----
```

And for verification use key_public.pem:

```text
-----BEGIN CERTIFICATE-----
MIIBxDCCAW6gAwIBAgIQxUSX...
-----END CERTIFICATE-----
```

### What the parser accepts

`toPem()`, `pemToDer()` and `pemCertificates()` read
[RFC 7468](https://www.rfc-editor.org/rfc/rfc7468) textual messages, and `toPem()` also reads bare
base64 with a label supplied by the caller. Either form is judged by the same rules, and `toPem()`
returns the same certificate whatever it arrived as: `\n` line endings, lines of 64 characters,
one message after another.

- `toPem(value, label?)` returns canonical PEM. A Buffer that opens with an encapsulation
  boundary is read as the bytes of a PEM file and any other as raw DER, so base64 text is given
  as a string rather than a Buffer.
- `pemToDer(pem)` returns the decoded bytes of the one message a value holds.
- `pemCertificates(pem)` returns the base64 of each `CERTIFICATE` message and ignores messages of
  any other label, so a private key in the same value is never published. It reads certificates
  out of a larger value, passing over the explanatory text tools write around a message, while
  `toPem()` rewrites the whole value and so must account for all of it.

Accepted:

- `\n`, `\r\n` and `\r` line endings, and a leading UTF-8 BOM.
- any line width, a single line included.
- spaces and tabs anywhere in the encapsulated data. XMLDSig carries a certificate as
  [`xs:base64Binary`](https://www.w3.org/TR/xmlschema11-2/#base64Binary), whose lexical space
  collapses whitespace, so a pretty-printed document indents it and a value that has been through
  a text field may have had its line endings replaced by spaces.
- a blank line after the header, and a blank line anywhere among the lines of base64 given
  without boundaries, which is the form an `X509Certificate` element carries. A blank line inside
  a message's body is rejected; RFC 7468's body does not have one.
- explanatory text before, after or between the messages, which `pemCertificates()` passes over.
  [Section 5.2](https://www.rfc-editor.org/rfc/rfc7468#section-5.2) shows a certificate written
  under its subject and issuer lines, and OpenSSL and keytool both write them.
- several messages in one value, of which `toPem()` keeps all, `pemCertificates()` takes the
  certificates, and `pemToDer()` takes none.
- any non-empty label of up to 48 characters that RFC 7468's grammar allows, which is every
  registered label and the ones OpenSSL adds, such as `RSA PRIVATE KEY`. `PemLabel` names the
  registered ones, the longest of which is 21 characters.
- a certificate encoded as BER as well as DER, as
  [RFC 7468 section 5.1](https://www.rfc-editor.org/rfc/rfc7468#section-5.1) allows. Its octets are
  kept as given, because [XML Signature 1.1](https://www.w3.org/TR/xmldsig-core1/#sec-X509Data)
  says an implementation SHOULD NOT alter or re-encode a certificate.
- base64 whose pad bits are not zero, which is written back out with them zeroed, since only that
  form is in [`xs:base64Binary`](https://www.w3.org/TR/xmlschema11-2/#base64Binary)'s lexical space.
  The octets are the same either way.
- the `Proc-Type` and `DEK-Info` header fields of a traditional encrypted private key, as OpenSSL
  and Node write one, so that `pemCertificates()` can read certificates out of a bundle holding
  such a key. `toPem()` and `pemToDer()` refuse the key itself, whose data is lost without them.

Rejected, with an error rather than a certificate:

- data outside the base64 alphabet, padding away from the end, or a final quantum that is not
  whole, per [RFC 4648 section 4](https://www.rfc-editor.org/rfc/rfc4648#section-4).
- a `CERTIFICATE` whose data is not exactly one X.509 certificate: base64 of something else, a
  certificate cut short, or one with more bytes after it. Node's
  [`X509Certificate`](https://nodejs.org/api/crypto.html#class-x509certificate) decides whether
  the data is a certificate, so it is judged as X.509 and not by its base64 alone.
- a header with no data under it, and a blank line in the middle of a message's data.
- a boundary sharing its line with other text.
  [Figure 1](https://www.rfc-editor.org/rfc/rfc7468#section-3) gives an encapsulation boundary a
  line of its own, so text on that line is not the explanatory text around a message.
- a value that opens a message it does not close, or one whose header and footer labels disagree.
  [Section 3](https://www.rfc-editor.org/rfc/rfc7468#section-3) permits a parser to disregard the
  footer's label, but OpenSSL will not read such a message, so neither does this one.
- an empty label, which the `label` production marks as `empty ok`. A message labelled nothing
  names no format, and OpenSSL answers one with `ERR_OSSL_UNSUPPORTED`, so `-----BEGIN -----` and
  `toPem(data, "")` are both refused.
- a label outside RFC 7468's grammar, which is one holding `--` or opening or closing with a
  blank, and one longer than 48 characters. A label is written into both boundaries, so one
  holding `--` would produce a message this parser could not read back, and `-----BEGIN ` and
  `-----` bracket it in 16 characters, so 48 is the longest whose boundary still fits one line.

### Converting .pfx certificates to pem

If you have .pfx certificates you can convert them to .pem using [openssl](http://www.openssl.org/):

```shell
openssl pkcs12 -in c:\certs\yourcert.pfx -out c:\certs\cag.pem
```

Then you could use the result as is for the purpose of signing. For the purpose of validation open the resulting .pem with a text editor and copy from -----BEGIN CERTIFICATE----- to -----END CERTIFICATE----- (including) to a new text file and save it as .pem.

## Examples

### how to add a prefix for the signature

Use the `prefix` option when calling `computeSignature` to add a prefix to the signature.

```javascript
const { SignedXml } = require("xml-crypto");
const fs = require("fs");

const xml = "<library><book><name>Harry Potter</name></book></library>";

const sig = new SignedXml({
  privateKey: fs.readFileSync("client.pem"),
  canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
  signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
});
sig.addReference({
  xpath: "//*[local-name(.)='book']",
  digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
});
sig.computeSignature(xml, {
  prefix: "ds",
});
```

### how to specify the location of the signature

Use the `location` option when calling `computeSignature` to move the signature around. Set
`reference` to an XPath expression that selects a node (default `/*`, the document element), and
`action` to one of the following:

- `append` (default) - insert the signature as the last child of the `reference` node
- `prepend` - insert the signature as the first child of the `reference` node
- `before` - insert the signature just before the `reference` node
- `after` - insert the signature just after the `reference` node

```javascript
const { SignedXml } = require("xml-crypto");
const fs = require("fs");

const xml = "<library><book><name>Harry Potter</name></book></library>";

const sig = new SignedXml({
  privateKey: fs.readFileSync("client.pem"),
  canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
  signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
});
sig.addReference({
  xpath: "//*[local-name(.)='book']",
  digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
});
sig.computeSignature(xml, {
  location: { reference: "//*[local-name(.)='book']", action: "after" }, // This will place the signature after the book element
});
```

### How to add custom Objects to the signature

Use the `objects` option when creating a SignedXml instance to add custom Objects to the signature.

```javascript
const { SignedXml } = require("xml-crypto");
const fs = require("fs");

const xml = "<library><book><name>Harry Potter</name></book></library>";

const sig = new SignedXml({
  privateKey: fs.readFileSync("client.pem"),
  canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
  signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  objects: [
    {
      content: "<TestObject>Test data in Object</TestObject>",
      attributes: {
        Id: "Object1",
        MimeType: "text/xml",
      },
    },
  ],
});

// Add a reference to the Object element
sig.addReference({
  xpath: "//*[@Id='Object1']",
  digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
});

sig.computeSignature(xml);
fs.writeFileSync("signed.xml", sig.getSignedXml());
```

## Development

The testing framework we use is [Mocha](https://github.com/mochajs/mocha) with [Chai](https://github.com/chaijs/chai) as the assertion framework.

To run tests use:

```shell
npm test
```

## Sponsors

![Short-io logo](https://github.com/Short-io.png?size=30) [Short-io](https://github.com/Short-io)

![RideAmigosCorp logo](https://github.com/RideAmigosCorp.png?size=30) [RideAmigosCorp](https://github.com/RideAmigosCorp)

## Past sponsors

![stytchauth](https://github.com/stytchauth.png?size=30) [stytchauth](https://github.com/stytchauth)

## License

This project is licensed under the [MIT License](http://opensource.org/licenses/MIT). See the [LICENSE](LICENSE) file for more info.
