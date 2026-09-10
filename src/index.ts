export { C14nCanonicalization, C14nCanonicalizationWithComments } from "./c14n-canonicalization";
export {
  ExclusiveCanonicalization,
  ExclusiveCanonicalizationWithComments,
} from "./exclusive-canonicalization";
export { SignedXml } from "./signed-xml";

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
export { createOptionalCallbackFunction } from "./types";

// Key-format conversion, and the ancestor-namespace lookup an implementer of a custom
// canonicalization algorithm needs. Everything else in `./utils` is internal to this
// package: it is exported from that module for its siblings, not for consumers.
export { derToPem, findAncestorNs, normalizePem, pemToDer } from "./utils";
