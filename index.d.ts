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
  | "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

type TransformAlgorithmType =
  | CanonicalizationAlgorithmType
  | "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
  | string;

type HashAlgorithmType =
  | "http://www.w3.org/2000/09/xmldsig#sha1"
  | "http://www.w3.org/2001/04/xmlenc#sha256"
  | "http://www.w3.org/2001/04/xmlenc#sha512"
  | string;

type SignatureAlgorithmType =
  | "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
  | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
  | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
  | "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
  | string;

/**
 * Options for the SignedXml constructor.
 */
type SignedXmlOptions = {
  canonicalizationAlgorithm?: TransformAlgorithmType;
  inclusiveNamespacesPrefixList?: string;
  idAttribute?: string;
  implicitTransforms?: ReadonlyArray<TransformAlgorithmType>;
  signatureAlgorithm?: SignatureAlgorithmType;
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
 * Callback signature for the {@link SignedXml#computeSignature} method.
 */
type ComputeSignatureCallback = (error: Error | null, signature: SignedXml | null) => void;

/**
 * Represents a reference node for XML digital signature.
 */
export interface Reference {
  // The XPath expression that selects the data to be signed.
  xpath: string;

  // Optional. An array of transforms to be applied to the data before signing.
  transforms?: ReadonlyArray<TransformAlgorithmType>;

  // Optional. The algorithm used to calculate the digest value of the data.
  digestAlgorithm?: HashAlgorithmType;

  // Optional. The URI that identifies the data to be signed.
  uri?: string;

  // Optional. The digest value of the referenced data.
  digestValue?: string;

  // Optional. A list of namespace prefixes to be treated as "inclusive" during canonicalization.
  inclusiveNamespacesPrefixList?: string;

  // Optional. Indicates whether the URI is empty.
  isEmptyUri?: boolean;
}

/** Implement this to create a new HashAlgorithm */
export interface HashAlgorithm {
  getAlgorithmName(): HashAlgorithmType;

  getHash(xml: string): string;
}

/** Implement this to create a new SignatureAlgorithm */
export interface SignatureAlgorithm {
  getAlgorithmName(): SignatureAlgorithmType;

  getSignature(signedInfo: Node, signingKey: Buffer): string;
}

/** Implement this to create a new TransformAlgorithm */
export interface TransformAlgorithm {
  getAlgorithmName(): TransformAlgorithmType;

  process(node: Node): string;
}

/**
 * ### Sign
 * #### Properties
 * - {@link SignedXml#signingKey} [required]
 * - {@link SignedXml#keyInfoProvider} [optional]
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
 * -  {@link SignedXml#keyInfoProvider} [required]
 * #### Api
 *  - {@link SignedXml#loadSignature}
 *  - {@link SignedXml#checkSignature}
 *  - {@link SignedXml#validationErrors}
 */

/**
 * @param cert the certificate as a string or array of strings (see https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-X509Data)
 * @param prefix an optional namespace alias to be used for the generated XML
 */
export interface GetKeyInfoContentArgs {
  cert: string | string[] | Buffer;
  prefix: string;
}

export class SignedXml {
  // To add a new transformation algorithm create a new class that implements the {@link TransformationAlgorithm} interface, and register it here. More info: {@link https://github.com/node-saml/xml-crypto#customizing-algorithms|Customizing Algorithms}
  static CanonicalizationAlgorithms: {
    [uri in TransformAlgorithmType]: new () => TransformAlgorithm;
  };
  // To add a new hash algorithm create a new class that implements the {@link HashAlgorithm} interface, and register it here. More info: {@link https://github.com/node-saml/xml-crypto#customizing-algorithms|Customizing Algorithms}
  static HashAlgorithms: { [uri in HashAlgorithmType]: new () => HashAlgorithm };
  // To add a new signature algorithm create a new class that implements the {@link SignatureAlgorithm} interface, and register it here. More info: {@link https://github.com/node-saml/xml-crypto#customizing-algorithms|Customizing Algorithms}
  static SignatureAlgorithms: { [uri in SignatureAlgorithmType]: new () => SignatureAlgorithm };
  // Rules used to convert an XML document into its canonical form.
  canonicalizationAlgorithm: TransformAlgorithmType;
  // It specifies a list of namespace prefixes that should be considered "inclusive" during the canonicalization process.
  inclusiveNamespacesPrefixList: string;
  // The structure for managing keys and KeyInfo section in XML data. See {@link KeyInfoProvider}
  keyInfoProvider: KeyInfoProvider;
  // Specifies the data to be signed within an XML document. See {@link Reference}
  references: Reference[];
  // One of the supported signature algorithms. See {@link SignatureAlgorithmType}
  signatureAlgorithm: SignatureAlgorithmType;
  // A {@link Buffer} or pem encoded {@link String} containing your private key
  privateKey: Buffer | string;
  // Contains validation errors (if any) after {@link checkSignature} method is called
  validationErrors: string[];

  /**
   * The SignedXml constructor provides an abstraction for sign and verify xml documents. The object is constructed using
   * @param idMode  if the value of "wssecurity" is passed it will create/validate id's with the ws-security namespace.
   * @param options {@link SignedXmlOptions
   */
  constructor(idMode?: "wssecurity" | null, options?: SignedXmlOptions);

  /**
   * Due to key-confusion issues, it's risky to have both hmac
   * and digital signature algorithms enabled at the same time.
   * This enables HMAC and disables other signing algorithms.
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
    transforms?: TransformAlgorithmType[],
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
   * @returns `this` (the instance of SignedXml).
   * @throws TypeError If the xml can not be parsed.
   */
  computeSignature(xml: string): SignedXml;

  /**
   * Compute the signature of the given XML (using the already defined settings).
   *
   * @param xml The XML to compute the signature for.
   * @param callback A callback function to handle the signature computation asynchronously.
   * @returns void
   * @throws TypeError If the xml can not be parsed.
   */
  computeSignature(xml: string, callback: ComputeSignatureCallback): void;

  /**
   * Compute the signature of the given XML (using the already defined settings).
   *
   * @param xml The XML to compute the signature for.
   * @param opts An object containing options for the signature computation.
   * @returns If no callback is provided, returns `this` (the instance of SignedXml).
   * @throws TypeError If the xml can not be parsed, or Error if there were invalid options passed.
   */
  computeSignature(xml: string, opts: ComputeSignatureOptions): SignedXml;

  /**
   * Compute the signature of the given XML (using the already defined settings).
   *
   * @param xml The XML to compute the signature for.
   * @param opts An object containing options for the signature computation.
   * @param callback A callback function to handle the signature computation asynchronously.
   * @returns void
   * @throws TypeError If the xml can not be parsed, or Error if there were invalid options passed.
   */
  computeSignature(
    xml: string,
    opts: ComputeSignatureOptions,
    callback: ComputeSignatureCallback
  ): void;

  /**
   * Returns just the signature part, must be called only after {@link computeSignature}
   *
   * @returns The signature XML.
   */
  getSignatureXml(): string;

  /**
   * Returns the original xml with Id attributes added on relevant elements (required for validation), must be called only after {@link computeSignature}
   *
   * @returns The original XML with IDs.
   */
  getOriginalXmlWithIds(): string;

  /**
   * Returns the original xml document with the signature in it, must be called only after {@link computeSignature}
   *
   * @returns The signed XML.
   */
  getSignedXml(): string;

  /**
   * Builds the contents of a KeyInfo element as an XML string.
   *
   * For example, if the value of the prefix argument is 'foo', then
   * the resultant XML string will be "<foo:X509Data></foo:X509Data>"
   *
   * @return an XML string representation of the contents of a KeyInfo element, or `null` if no `KeyInfo` element should be included
   */
  getKeyInfoContent(args: GetKeyInfoContentArgs): string | null;

  /**
   * Returns the value of the signing certificate based on the contents of the
   * specified KeyInfo.
   *
   * @param keyInfo an array with exactly one KeyInfo element (see https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-X509Data)
   * @return the signing certificate as a string in PEM format
   */
  getCertFromKeyInfo(keyInfo: string): string | null;
}

export interface Utils {
  /**
   * @param pem The PEM-encoded base64 certificate to strip headers from
   */
  static pemToDer(pem: string): string;

  /**
   * @param der The DER-encoded base64 certificate to add PEM headers too
   * @param pemLabel The label of the header and footer to add
   */
  static derToPem(
    der: string,
    pemLabel: ["CERTIFICATE" | "PRIVATE KEY" | "RSA PUBLIC KEY"]
  ): string;

  /**
   * -----BEGIN [LABEL]-----
   * base64([DATA])
   * -----END [LABEL]-----
   *
   * Above is shown what PEM file looks like. As can be seen, base64 data
   * can be in single line or multiple lines.
   *
   * This function normalizes PEM presentation to;
   *  - contain PEM header and footer as they are given
   *  - normalize line endings to '\n'
   *  - normalize line length to maximum of 64 characters
   *  - ensure that 'preeb' has line ending '\n'
   *
   * With couple of notes:
   *  - 'eol' is normalized to '\n'
   *
   * @param pem The PEM string to normalize to RFC7468 'stricttextualmsg' definition
   */
  static normalizePem(pem: string): string;

  /**
   * PEM format has wide range of usages, but this library
   * is enforcing RFC7468 which focuses on PKIX, PKCS and CMS.
   *
   * https://www.rfc-editor.org/rfc/rfc7468
   *
   * PEM_FORMAT_REGEX is validating given PEM file against RFC7468 'stricttextualmsg' definition.
   *
   * With few exceptions;
   *  - 'posteb' MAY have 'eol', but it is not mandatory.
   *  - 'preeb' and 'posteb' lines are limited to 64 characters, but
   *     should not cause any issues in context of PKIX, PKCS and CMS.
   */
  PEM_FORMAT_REGEX: RegExp;
  EXTRACT_X509_CERTS: RegExp;
  BASE64_REGEX: RegExp;
}

/**
 * {@link https://github.com/goto100/xpath/blob/HEAD/README.md|xpath} options
 * Uses the `xpath` package's select method to perform an XPath query on an XML node.
 *
 * @param {Node} node - The node to perform the XPath query on.
 * @param {string} xpath - The XPath query string.
 * @returns {SelectedValue[]} The values selected by the XPath query.
 */
export function xpath(node: Node, xpath: string): SelectedValue[];
