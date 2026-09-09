export { C14nCanonicalization, C14nCanonicalizationWithComments } from "./c14n-canonicalization";
export {
  ExclusiveCanonicalization,
  ExclusiveCanonicalizationWithComments,
} from "./exclusive-canonicalization";
export { SignedXml } from "./signed-xml";

// These lists replace `export * from` and are exhaustive on purpose: they
// reproduce the surface the wildcards already published, so that narrowing it
// becomes a deliberate, separately reviewable break rather than a side effect.
export { createOptionalCallbackFunction } from "./types";
export type {
  CanonicalizationAlgorithmType,
  CanonicalizationOrTransformAlgorithmType,
  CanonicalizationOrTransformationAlgorithm,
  CanonicalizationOrTransformationAlgorithmProcessOptions,
  ComputeSignatureOptions,
  ComputeSignatureOptionsLocation,
  ErrorFirstCallback,
  GetKeyInfoContentArgs,
  HashAlgorithm,
  HashAlgorithmType,
  NamespacePrefix,
  ObjectAttributes,
  Reference,
  RenderedNamespace,
  SignatureAlgorithm,
  SignatureAlgorithmType,
  SignedXmlOptions,
  TransformAlgorithm,
} from "./types";

export {
  BASE64_REGEX,
  EXTRACT_X509_CERTS,
  PEM_FORMAT_REGEX,
  derToPem,
  encodeSpecialCharactersInAttribute,
  encodeSpecialCharactersInText,
  findAncestorNs,
  findAncestorNsForNode,
  findAttr,
  findChildren,
  // Deprecated alias of `findChildren`, still published because `export *` did.
  // Removal tracked in https://github.com/node-saml/xml-crypto/issues/550
  // eslint-disable-next-line deprecation/deprecation
  findChilds,
  isArrayHasLength,
  isDescendantOf,
  normalizePem,
  pemToDer,
  validateDigestValue,
} from "./utils";
