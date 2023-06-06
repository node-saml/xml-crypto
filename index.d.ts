// Type definitions for @node-saml/xml-crypto
// Project: https://github.com/node-saml/xml-crypto#readme
// Original definitions by: Eric Heikes <https://github.com/eheikes>
//                          Max Chehab <https://github.com/maxchehab>

/// <reference types="node" />

import { SelectedValue } from "xpath";

type CanonicalizationAlgorithmType =
  | "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
  | "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
  | "http://www.w3.org/2001/10/xml-exc-c14n#"
  | "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
  | "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

type HashAlgorithmType =
  | "http://www.w3.org/2000/09/xmldsig#sha1"
  | "http://www.w3.org/2001/04/xmlenc#sha256"
  | "http://www.w3.org/2001/04/xmlenc#sha512";

type SignatureAlgorithmType =
  | "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
  | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
  | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
  | "http://www.w3.org/2000/09/xmldsig#hmac-sha1";

/**
 * Options for the SignedXml constructor.
 */
type SignedXmlOptions = {
  canonicalizationAlgorithm?: CanonicalizationAlgorithmType | undefined;
  inclusiveNamespacesPrefixList?: string | undefined;
  idAttribute?: string | undefined;
  implicitTransforms?: ReadonlyArray<CanonicalizationAlgorithmType> | undefined;
  signatureAlgorithm?: SignatureAlgorithmType | undefined;
};

/**
 * Options for the computeSignature method.
 */
type ComputeSignatureOptions = {
  prefix?: string;
  attrs?: { [attrName: string]: string };
  location?: {
    reference?: string;
    action?: "append" | "prepend" | "before" | "after";
  };
  existingPrefixes?: { [prefix: string]: string };
};

/**
 * Callback signature for the computeSignature method.
 */
type ComputeSignatureCallback = (error: Error | null, signature: SignedXml | null) => void;

export interface Reference {
  xpath: string;
  transforms?: ReadonlyArray<CanonicalizationAlgorithmType> | undefined;
  digestAlgorithm?: HashAlgorithmType | undefined;
  uri?: string | undefined;
  digestValue?: string | undefined;
  inclusiveNamespacesPrefixList?: string | undefined;
  isEmptyUri?: boolean | undefined;
}

export interface HashAlgorithm {
  getAlgorithmName(): string;

  getHash(xml: string): string;
}

export interface SignatureAlgorithm {
  getAlgorithmName(): string;

  getSignature(signedInfo: Node, signingKey: Buffer): string;
}

export interface TransformationAlgorithm {
  getAlgorithmName(): string;

  process(node: Node): string;
}

export class SignedXml {
  static CanonicalizationAlgorithms: {
    [uri in CanonicalizationAlgorithmType]: new () => TransformationAlgorithm;
  };
  static HashAlgorithms: { [uri in HashAlgorithmType]: new () => HashAlgorithm };
  static SignatureAlgorithms: { [uri in SignatureAlgorithmType]: new () => SignatureAlgorithm };
  canonicalizationAlgorithm: CanonicalizationAlgorithmType;
  inclusiveNamespacesPrefixList: string;
  keyInfoProvider: KeyInfo;
  references: Reference[];
  signatureAlgorithm: SignatureAlgorithmType;
  signingKey: Buffer | string;
  validationErrors: string[];

  constructor(idMode?: string | null, options?: SignedXmlOptions);

  /**
   * Due to key-confusion issues, its risky to have both hmac
   * and digital signature algos enabled at the same time.
   * This enables HMAC and disables other signing algos.
   */
  enableHMAC(): void;

  /**
   * Validates the signature of the provided XML document synchronously using the configured key info provider.
   *
   * @param xml The XML document containing the signature to be validated.
   * @returns `true` if the signature is valid
   * @throws Error if no key info resolver is provided.
   */
  checkSignature(xml: string): boolean;

  /**
   * Validates the signature of the provided XML document asynchronously using the configured key info provider.
   *
   * @param xml The XML document containing the signature to be validated.
   * @param callback Callback function to handle the validation result asynchronously.
   * @throws Error if the last parameter is provided and is not a function, or if no key info resolver is provided.
   */
  checkSignature(xml: string, callback: (error: Error | null, isValid?: boolean) => void): void;

  /**
   * Loads the signature information from the provided XML node or string.
   *
   * @param signatureNode The XML node or string representing the signature.
   * @throws Error if the canonicalization or signature method elements are not found, or if there are no reference elements.
   */
  loadSignature(signatureNode: Node | string): void;

  /**
   * Adds a reference to the signature.
   *
   * @param xpath The XPath expression to select the XML nodes to be referenced.
   * @param transforms An array of transform algorithms to be applied to the selected nodes. Defaults to ["http://www.w3.org/2001/10/xml-exc-c14n#"].
   * @param digestAlgorithm The digest algorithm to use for computing the digest value. Defaults to "http://www.w3.org/2000/09/xmldsig#sha1".
   * @param uri The URI identifier for the reference. If empty, an empty URI will be used.
   * @param digestValue The expected digest value for the reference.
   * @param inclusiveNamespacesPrefixList The prefix list for inclusive namespace canonicalization.
   * @param isEmptyUri Indicates whether the URI is empty. Defaults to `false`.
   */
  addReference(
    xpath: string,
    transforms?: CanonicalizationAlgorithmType[],
    digestAlgorithm?: HashAlgorithmType,
    uri?: string,
    digestValue?: string,
    inclusiveNamespacesPrefixList?: string,
    isEmptyUri?: boolean
  ): void;

  /**
   * Compute the signature of the given XML (using the already defined settings).
   *
   * @param xml The XML to compute the signature for.
   * @returns If no callback is provided, returns `this` (the instance of SignedXml).
   */
  computeSignature(xml: string): SignedXml;

  /**
   * Compute the signature of the given XML (using the already defined settings).
   *
   * @param xml The XML to compute the signature for.
   * @param callback A callback function to handle the signature computation asynchronously.
   * @returns void
   */
  computeSignature(xml: string, callback: ComputeSignatureCallback): void;

  /**
   * Compute the signature of the given XML (using the already defined settings).
   *
   * @param xml The XML to compute the signature for.
   * @param opts An object containing options for the signature computation.
   * @returns If no callback is provided, returns `this` (the instance of SignedXml).
   * @throws If the `location.action` option has an invalid action value.
   */
  computeSignature(xml: string, opts: ComputeSignatureOptions): SignedXml;

  /**
   * Compute the signature of the given XML (using the already defined settings).
   *
   * @param xml The XML to compute the signature for.
   * @param opts An object containing options for the signature computation.
   * @param callback A callback function to handle the signature computation asynchronously.
   * @returns void
   * @throws If the `location.action` option has an invalid action value.
   */
  computeSignature(
    xml: string,
    opts: ComputeSignatureOptions,
    callback: ComputeSignatureCallback
  ): void;

  /**
   * Get the signature XML as a string.
   *
   * @returns The signature XML.
   */
  getSignatureXml(): string;

  /**
   * Get the original XML with IDs as a string.
   *
   * @returns The original XML with IDs.
   */
  getOriginalXmlWithIds(): string;

  /**
   * Get the signed XML as a string.
   *
   * @returns The signed XML.
   */
  getSignedXml(): string;
}

export interface KeyInfo {
  getKey(keyInfo?: Node[] | null): Buffer;

  getKeyInfo(key?: string, prefix?: string): string;

  attrs?: { [key: string]: any } | undefined;
}

export class FileKeyInfo implements KeyInfo {
  file: string;

  constructor(file?: string);

  getKey(keyInfo?: Node[] | null): Buffer;

  getKeyInfo(key?: string, prefix?: string): string;
}

export class StringKeyInfo implements KeyInfo {
  key: string;

  constructor(key?: string);

  getKey(keyInfo?: Node[] | null): Buffer;

  getKeyInfo(key?: string, prefix?: string): string;
}

export function xpath(node: Node, xpath: string): SelectedValue[];
