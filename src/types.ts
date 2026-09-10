/* eslint-disable no-unused-vars */
// Type definitions for @node-saml/xml-crypto
// Project: https://github.com/node-saml/xml-crypto#readme
// Original definitions by: Eric Heikes <https://github.com/eheikes>
//                          Max Chehab <https://github.com/maxchehab>

/// <reference types="node" />

import * as crypto from "crypto";

export type CanonicalizationAlgorithmType =
  | "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
  | "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
  | "http://www.w3.org/2001/10/xml-exc-c14n#"
  | "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
  | string;

export type CanonicalizationOrTransformAlgorithmType =
  CanonicalizationAlgorithmType | "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

export type HashAlgorithmType =
  | "http://www.w3.org/2000/09/xmldsig#sha1"
  | "http://www.w3.org/2001/04/xmlenc#sha256"
  | "http://www.w3.org/2001/04/xmlenc#sha512"
  | string;

export type SignatureAlgorithmType =
  | "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
  | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
  | "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"
  | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
  | "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
  | string;

/**
 * @param cert the certificate as a string or array of strings (@see https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-X509Data)
 * @param prefix an optional namespace alias to be used for the generated XML
 */
export interface GetKeyInfoContentArgs {
  publicCert?: crypto.KeyLike;
  prefix?: string | null;
}

/**
 * Object attributes as defined in XMLDSig spec and are emitted verbatim
 * @see https://www.w3.org/TR/xmldsig-core/#sec-Object
 */
export interface ObjectAttributes {
  /** Optional ID attribute */
  Id?: string;
  /** Optional MIME type attribute */
  MimeType?: string;
  /** Optional encoding attribute */
  Encoding?: string;
  /** Any additional custom attributes */
  [key: string]: string | undefined;
}

/**
 * Options for the SignedXml constructor.
 */
export interface SignedXmlOptions {
  idMode?: "wssecurity";
  idAttribute?: string;
  privateKey?: crypto.KeyLike;
  publicCert?: crypto.KeyLike;
  signatureAlgorithm?: SignatureAlgorithmType;
  canonicalizationAlgorithm?: CanonicalizationAlgorithmType;
  inclusiveNamespacesPrefixList?: string | string[];
  implicitTransforms?: ReadonlyArray<CanonicalizationOrTransformAlgorithmType>;
  keyInfoAttributes?: Record<string, string>;
  getKeyInfoContent?(args?: GetKeyInfoContentArgs): string | null;
  getCertFromKeyInfo?(keyInfo?: Node | null): string | null;
  objects?: Array<{ content: string; attributes?: ObjectAttributes }>;
}

export interface NamespacePrefix {
  prefix: string;
  namespaceURI: string;
}

export interface RenderedNamespace {
  rendered: string;
  newDefaultNs: string;
}

export interface CanonicalizationOrTransformationAlgorithmProcessOptions {
  defaultNs?: string;
  defaultNsForPrefix?: Record<string, string>;
  ancestorNamespaces?: NamespacePrefix[];
  signatureNode?: Node | null;
  inclusiveNamespacesPrefixList?: string[];
}

export interface ComputeSignatureOptionsLocation {
  reference?: string;
  action?: "append" | "prepend" | "before" | "after";
}

/**
 * Options for the computeSignature method.
 *
 * - `prefix` {String} Adds a prefix for the generated signature tags
 * - `attrs` {Object} A hash of attributes and values `attrName: value` to add to the signature root node
 * - `location` {{ reference: String, action: String }}
 * - `existingPrefixes` {Object} A hash of prefixes and namespaces `prefix: namespace` already in the xml
 *   An object with a `reference` key which should
 *   contain a XPath expression, an `action` key which
 *   should contain one of the following values:
 *   `append`, `prepend`, `before`, `after`
 */
export interface ComputeSignatureOptions {
  prefix?: string;
  attrs?: Record<string, string>;
  location?: ComputeSignatureOptionsLocation;
  existingPrefixes?: Record<string, string>;
}

/**
 * Represents a reference node for XML digital signature.
 */
export interface Reference {
  // The XPath expression that selects the data to be signed.
  xpath?: string;

  // An array of transforms to be applied to the data before signing.
  transforms: ReadonlyArray<CanonicalizationOrTransformAlgorithmType>;

  // The algorithm used to calculate the digest value of the data.
  digestAlgorithm: HashAlgorithmType;

  // The URI that identifies the data to be signed.
  uri: string;

  // Optional. The digest value of the referenced data.
  digestValue?: unknown;

  // A list of namespace prefixes to be treated as "inclusive" during canonicalization.
  inclusiveNamespacesPrefixList: string[];

  // Optional. Indicates whether the URI is empty.
  isEmptyUri: boolean;

  // Optional. The `Id` attribute of the reference node.
  id?: string;

  // Optional. The `Type` attribute of the reference node.
  type?: string;

  // Optional. The type of the reference node.
  ancestorNamespaces?: NamespacePrefix[];

  validationError?: Error;

  getValidatedNode(xpathSelector?: string): Node | null;

  signedReference?: string;
}

/** Implement this to create a new CanonicalizationOrTransformationAlgorithm */
export interface CanonicalizationOrTransformationAlgorithm {
  process(
    node: Node,
    options: CanonicalizationOrTransformationAlgorithmProcessOptions,
  ): Node | string;

  getAlgorithmName(): CanonicalizationOrTransformAlgorithmType;
}

/**
 * Implement this to create a new HashAlgorithm.
 *
 * Provide `getHash`, `getHashAsync`, or both — an implementation backed by `node:crypto` can
 * answer synchronously, one backed by `crypto.subtle` cannot. Providing only `getHashAsync`
 * makes the algorithm usable from {@link SignedXml.computeSignatureAsync} and
 * {@link SignedXml.checkSignatureAsync}, and the synchronous entry points will say so rather
 * than failing obscurely.
 *
 * @see https://github.com/node-saml/xml-crypto/issues/546
 */
export interface HashAlgorithm {
  getAlgorithmName(): HashAlgorithmType;

  getHash?(xml: string): string;

  getHashAsync?(xml: string): Promise<string>;
}

/**
 * Extend this to create a new SignatureAlgorithm.
 *
 * Each operation comes in a synchronous and an asynchronous form; provide whichever the
 * backing implementation can support. A `node:crypto`-backed algorithm implements
 * `getSignature` and `verifySignature`; one backed by `crypto.subtle`, an HSM, a KMS or a
 * signing server implements `getSignatureAsync` and `verifySignatureAsync` and is used
 * through {@link SignedXml.computeSignatureAsync} and {@link SignedXml.checkSignatureAsync}.
 * An algorithm that only signs need not implement verification, and vice versa.
 *
 * @see https://github.com/node-saml/xml-crypto/issues/546
 */
export interface SignatureAlgorithm {
  /**
   * Sign the given string using the given key
   */
  getSignature?(signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string;

  /**
   * Sign the given string using the given key, resolving when the signature is available
   */
  getSignatureAsync?(signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): Promise<string>;

  /**
   * Verify the given signature of the given string using key
   *
   * @param key a public cert, public key, or private key can be passed here
   */
  verifySignature?(material: string, key: crypto.KeyLike, signatureValue: string): boolean;

  /**
   * Verify the given signature of the given string using key, resolving with the verdict
   *
   * @param key a public cert, public key, or private key can be passed here
   */
  verifySignatureAsync?(
    material: string,
    key: crypto.KeyLike,
    signatureValue: string,
  ): Promise<boolean>;

  getAlgorithmName(): SignatureAlgorithmType;
}

/** Implement this to create a new TransformAlgorithm */
export interface TransformAlgorithm {
  getAlgorithmName(): CanonicalizationOrTransformAlgorithmType;

  process(node: Node): string;
}

/**
 * ### Sign
 * #### Properties
 * - {@link SignedXml#privateKey} [required]
 * - {@link SignedXml#publicCert} [optional]
 * - {@link SignedXml#signatureAlgorithm} [optional]
 * - {@link SignedXml#canonicalizationAlgorithm} [optional]
 * #### Api
 *  - {@link SignedXml#addReference}
 *  - {@link SignedXml#computeSignature}
 *  - {@link SignedXml#getSignedXml}
 *  - {@link SignedXml#getSignatureXml}
 *  - {@link SignedXml#getOriginalXmlWithIds}
 *
 * ### Verify
 * #### Properties
 * -  {@link SignedXml#publicCert} [optional]
 * #### Api
 *  - {@link SignedXml#loadSignature}
 *  - {@link SignedXml#checkSignature}
 */
