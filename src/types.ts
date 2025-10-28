/* eslint-disable no-unused-vars */
// Type definitions for @node-saml/xml-crypto
// Project: https://github.com/node-saml/xml-crypto#readme
// Original definitions by: Eric Heikes <https://github.com/eheikes>
//                          Max Chehab <https://github.com/maxchehab>

/// <reference types="node" />

import * as crypto from "crypto";
import { Algorithms } from "./constants";

export type ErrorFirstCallback<T> = (err: Error | null, result?: T) => void;

export type IdAttributeType =
  | string
  | { prefix: string; localName: string; namespaceUri: string }
  | { localName: string; namespaceUri: string | undefined };

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

export type SignatureAlgorithmName =
  | (typeof Algorithms.signature)[keyof typeof Algorithms.signature]
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

  getAlgorithmName(): SignatureAlgorithmName;
}
export type SignatureAlgorithmMap = Record<SignatureAlgorithmName, new () => SignatureAlgorithm>;

export type HashAlgorithmName = (typeof Algorithms.hash)[keyof typeof Algorithms.hash] | string;
/** Implement this to create a new HashAlgorithm */
export interface HashAlgorithm {
  getAlgorithmName(): HashAlgorithmName;

  getHash(xml: string): string;
}
export type HashAlgorithmMap = Record<HashAlgorithmName, new () => HashAlgorithm>;

export type TransformAlgorithmName =
  | (typeof Algorithms.transform)[keyof typeof Algorithms.transform]
  | string;
/** Implement this to create a new TransformAlgorithm */
export interface TransformAlgorithm {
  getAlgorithmName(): TransformAlgorithmName;

  process(node: Node, options: TransformAlgorithmOptions): string | Node;
}
export type TransformAlgorithmMap = Record<TransformAlgorithmName, new () => TransformAlgorithm>;

export type CanonicalizationAlgorithmName =
  | (typeof Algorithms.canonicalization)[keyof typeof Algorithms.canonicalization]
  | string;
/** Implement this to create a new CanonicalizationAlgorithm */
export interface CanonicalizationAlgorithm extends TransformAlgorithm {
  getAlgorithmName(): CanonicalizationAlgorithmName;

  // TODO: after  canonicalization algorithms algorithms are separated from transform algorithms,
  //       set process to return string only
  process(node: Node, options: TransformAlgorithmOptions): string | Node;
}
export type CanonicalizationAlgorithmMap = Record<
  CanonicalizationAlgorithmName,
  new () => CanonicalizationAlgorithm
>;
/**
 * Options for the SignedXml constructor.
 */
export interface SignedXmlOptions {
  idMode?: "wssecurity";
  idAttribute?: IdAttributeType;
  idAttributes?: IdAttributeType[];
  privateKey?: crypto.KeyLike;
  publicCert?: crypto.KeyLike;
  signatureAlgorithm?: SignatureAlgorithmName;
  canonicalizationAlgorithm?: CanonicalizationAlgorithmName;
  inclusiveNamespacesPrefixList?: string | string[];
  maxTransforms?: number | null;
  implicitTransforms?: ReadonlyArray<TransformAlgorithmName>;
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
  transforms: ReadonlyArray<TransformAlgorithmName>;

  // The algorithm used to calculate the digest value of the data.
  digestAlgorithm: HashAlgorithmName;

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
