/* eslint-disable no-unused-vars */
// Type definitions for @node-saml/xml-crypto
// Project: https://github.com/node-saml/xml-crypto#readme
// Original definitions by: Eric Heikes <https://github.com/eheikes>
//                          Max Chehab <https://github.com/maxchehab>

/// <reference types="node" />

import * as crypto from "crypto";
import { XMLDSIG_URIS } from "./xmldsig-uris";
import { KeyLike, X509Certificate } from "node:crypto";
const { SIGNATURE_ALGORITHMS, HASH_ALGORITHMS, TRANSFORM_ALGORITHMS, CANONICALIZATION_ALGORITHMS } =
  XMLDSIG_URIS;

export type ErrorFirstCallback<T> = (err: Error | null, result?: T) => void;

export type SignatureIdAttributeType =
  | string
  | { prefix: string; localName: string; namespaceUri: string };
export type VerificationIdAttributeType =
  | string
  | { localName: string; namespaceUri: string | null };
export type IdAttributeType = SignatureIdAttributeType | VerificationIdAttributeType;

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

export type KeySelectorFunction = (keyInfo?: Node | null) => string | null;

export interface NamespacePrefix {
  prefix: string;
  namespaceURI: string;
}

export interface TransformAlgorithmOptions {
  defaultNs?: string;
  defaultNsForPrefix?: Record<string, string>;
  ancestorNamespaces?: NamespacePrefix[];
  signatureNode?: Node | null;
  inclusiveNamespacesPrefixList?: string[];
}

export type SignatureAlgorithmURI =
  | (typeof SIGNATURE_ALGORITHMS)[keyof typeof SIGNATURE_ALGORITHMS]
  | string;

/** Extend this to create a new SignatureAlgorithm */
export interface SignatureAlgorithm {
  /**
   * Sign the given string using the given key
   */
  getSignature(signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string;
  getSignature(
    signedInfo: crypto.BinaryLike,
    privateKey: crypto.KeyLike,
    callback?: ErrorFirstCallback<string>,
  ): void;
  /**
   * Verify the given signature of the given string using key
   *
   * @param key a public cert, public key, or private key can be passed here
   */
  verifySignature(material: string, key: crypto.KeyLike, signatureValue: string): boolean;
  verifySignature(
    material: string,
    key: crypto.KeyLike,
    signatureValue: string,
    callback?: ErrorFirstCallback<boolean>,
  ): void;

  getAlgorithmName(): SignatureAlgorithmURI;
}
export type SignatureAlgorithmMap = Record<SignatureAlgorithmURI, new () => SignatureAlgorithm>;

export type HashAlgorithmURI = (typeof HASH_ALGORITHMS)[keyof typeof HASH_ALGORITHMS] | string;
/** Implement this to create a new HashAlgorithm */
export interface HashAlgorithm {
  getAlgorithmName(): HashAlgorithmURI;

  getHash(xml: string): string;
}
export type HashAlgorithmMap = Record<HashAlgorithmURI, new () => HashAlgorithm>;

export type TransformAlgorithmURI =
  | (typeof TRANSFORM_ALGORITHMS)[keyof typeof TRANSFORM_ALGORITHMS]
  | string;
/** Implement this to create a new TransformAlgorithm */
export interface TransformAlgorithm {
  getAlgorithmName(): TransformAlgorithmURI;

  process(node: Node, options: TransformAlgorithmOptions): string | Node;
}
export type TransformAlgorithmMap = Record<TransformAlgorithmURI, new () => TransformAlgorithm>;

export type CanonicalizationAlgorithmURI =
  | (typeof CANONICALIZATION_ALGORITHMS)[keyof typeof CANONICALIZATION_ALGORITHMS]
  | string;
/** Implement this to create a new CanonicalizationAlgorithm */
export interface CanonicalizationAlgorithm extends TransformAlgorithm {
  getAlgorithmName(): CanonicalizationAlgorithmURI;

  // TODO: after  canonicalization algorithms algorithms are separated from transform algorithms,
  //       set process to return string only
  process(node: Node, options: TransformAlgorithmOptions): string | Node;
}
export type CanonicalizationAlgorithmMap = Record<
  CanonicalizationAlgorithmURI,
  new () => CanonicalizationAlgorithm
>;
/**
 * Options for the SignedXml constructor.
 */
export interface SignedXmlOptions {
  idMode?: "wssecurity";
  idAttribute?: SignatureIdAttributeType;
  idAttributes?: VerificationIdAttributeType[];
  privateKey?: crypto.KeyLike;
  publicCert?: crypto.KeyLike;
  signatureAlgorithm?: SignatureAlgorithmURI;
  canonicalizationAlgorithm?: CanonicalizationAlgorithmURI;
  inclusiveNamespacesPrefixList?: string | string[];
  maxTransforms?: number | null;
  implicitTransforms?: ReadonlyArray<TransformAlgorithmURI>;
  keyInfoAttributes?: Record<string, string>;
  getKeyInfoContent?(args?: GetKeyInfoContentArgs): string | null;
  getCertFromKeyInfo?: KeySelectorFunction;
  objects?: Array<{ content: string; attributes?: ObjectAttributes }>;
  allowedSignatureAlgorithms?: SignatureAlgorithmMap;
  allowedHashAlgorithms?: HashAlgorithmMap;
  allowedCanonicalizationAlgorithms?: CanonicalizationAlgorithmMap;
  allowedTransformAlgorithms?: TransformAlgorithmMap;
}

export interface RenderedNamespace {
  rendered: string;
  newDefaultNs: string;
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
  transforms: ReadonlyArray<TransformAlgorithmURI>;

  // The algorithm used to calculate the digest value of the data.
  digestAlgorithm: HashAlgorithmURI;

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

function isErrorFirstCallback<T>(
  possibleCallback: unknown,
): possibleCallback is ErrorFirstCallback<T> {
  return typeof possibleCallback === "function";
}

/**
 * This function will add a callback version of a sync function.
 *
 * This follows the factory pattern.
 * Just call this function, passing the function that you'd like to add a callback version of.
 */
export function createOptionalCallbackFunction<T, A extends unknown[]>(
  syncVersion: (...args: A) => T,
): {
  (...args: A): T;
  (...args: [...A, ErrorFirstCallback<T>]): void;
} {
  return ((...args: A | [...A, ErrorFirstCallback<T>]) => {
    const possibleCallback = args[args.length - 1];
    if (isErrorFirstCallback(possibleCallback)) {
      try {
        const result = syncVersion(...(args.slice(0, -1) as A));
        possibleCallback(null, result);
      } catch (err) {
        possibleCallback(err instanceof Error ? err : new Error("Unknown error"));
      }
    } else {
      return syncVersion(...(args as A));
    }
  }) as {
    (...args: A): T;
    (...args: [...A, ErrorFirstCallback<T>]): void;
  };
}

/*** XmlDSigVerifier types ***/

export type CertificateKeySelector = {
  /** Public certificate or key to use for verification */
  publicCert: KeyLike;
};

export type KeyInfoKeySelector = {
  /** Function to extract the public key from KeyInfo element */
  getCertFromKeyInfo: (keyInfo?: Node | null) => string | null;
};

export type SharedSecretKeySelector = {
  /** Shared secret key to use for HMAC verification */
  sharedSecretKey: KeyLike;
};

export type KeySelector = CertificateKeySelector | KeyInfoKeySelector | SharedSecretKeySelector;

/**
 * Common configuration options for XML-DSig verification (Base).
 */
export interface XmlDSigVerifierOptionsBase {
  /**
   * Names of XML attributes to treat as element identifiers.
   * @default {@link SignedXml.getDefaultIdAttributes()}
   */
  idAttributes?: VerificationIdAttributeType[];

  /**
   * Transforms to apply implicitly during canonicalization.
   */
  implicitTransforms?: ReadonlyArray<TransformAlgorithmURI>;

  /**
   * Whether to throw an exception on verification failure.
   * @default false
   */
  throwOnError?: boolean;
}

export interface XmlDSigVerifierSecurityOptions {
  /**
   * Maximum number of transforms allowed per Reference element.
   * Limits complexity to prevent denial-of-service attacks.
   * @default {@link SignedXml.DEFAULT_MAX_TRANSFORMS}
   */
  maxTransforms?: number;

  /**
   * Signature algorithms allowed during verification.
   *
   * @default {@link SignedXml.getDefaultAsymmetricSignatureAlgorithms()} {@link SignedXml.getDefaultSymmetricSignatureAlgorithms()}
   */
  signatureAlgorithms?: SignatureAlgorithmMap;

  /**
   * Hash algorithms allowed during verification.
   *
   * @default {@link SignedXml.getDefaultHashAlgorithms()}
   */
  hashAlgorithms?: HashAlgorithmMap;

  /**
   * Transform algorithms allowed during verification. (This must include canonicalization algorithms)
   *
   * @default all algorithms in {@link SignedXml.getDefaultTransformAlgorithms()}
   */
  transformAlgorithms?: TransformAlgorithmMap;

  /**
   * Canonicalization algorithms allowed during verification.
   *
   * @default all algorithms in {@link SignedXml.getDefaultCanonicalizationAlgorithms()}
   */
  canonicalizationAlgorithms?: CanonicalizationAlgorithmMap;
}

export interface KeyInfoXmlDSigSecurityOptions extends XmlDSigVerifierSecurityOptions {
  /**
   * Check certificate expiration dates during verification.
   * If true, signatures with expired certificates will be considered invalid.
   * This only applies when using KeyInfoKeySelector
   * @default true
   */
  checkCertExpiration?: boolean;

  /**
   * Optional truststore of trusted certificates
   * When provided, the certificate used to sign the XML must chain to one of these trusted certificates.
   * These must be PEM or DER encoded X509 certificates
   */
  truststore?: Array<string | Buffer | X509Certificate>;
}

/**
 * Configuration options for verification using KeyInfo.
 * Allows advanced security options for cert validation.
 */
export type KeyInfoXmlDSigVerifierOptions = XmlDSigVerifierOptionsBase & {
  /**
   * Function to extract the public key from KeyInfo element.
   */
  keySelector: KeyInfoKeySelector;

  /**
   * Security options for KeyInfo verification.
   */
  security?: KeyInfoXmlDSigSecurityOptions;
};

/**
 * Configuration options for verification using a provided public certificate.
 * Certificate validation options (e.g., expiration) are not applicable here.
 */
export type PublicCertXmlDSigVerifierOptions = XmlDSigVerifierOptionsBase & {
  /**
   * Public certificate or key to use for verification.
   */
  keySelector: CertificateKeySelector;

  /**
   * Basic security options for verification.
   */
  security?: XmlDSigVerifierSecurityOptions;
};

/**
 * Configuration options for verification using a shared secret (HMAC).
 */
export type SharedSecretXmlDSigVerifierOptions = XmlDSigVerifierOptionsBase & {
  /**
   * Shared secret key to use for HMAC verification.
   */
  keySelector: SharedSecretKeySelector;

  /**
   * Basic security options for verification.
   */
  security?: XmlDSigVerifierSecurityOptions;
};

export type XmlDSigVerifierOptions =
  | KeyInfoXmlDSigVerifierOptions
  | PublicCertXmlDSigVerifierOptions
  | SharedSecretXmlDSigVerifierOptions;

/**
 * Verification result containing the outcome and signed content.
 */
export type SuccessfulXmlDsigVerificationResult = {
  /** Whether the signature was successfully verified */
  success: true;
  error?: undefined;
  /** The canonicalized XML content that passed verification */
  signedReferences: string[];
};

export type FailedXmlDsigVerificationResult = {
  /** Whether the signature was successfully verified */
  success: false;
  /** Error message if verification failed */
  error: string;
  signedReferences?: undefined;
};

export type XmlDsigVerificationResult =
  | SuccessfulXmlDsigVerificationResult
  | FailedXmlDsigVerificationResult;
