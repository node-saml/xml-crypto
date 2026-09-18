import { deprecate } from "util";
import * as utils from "./utils";

export { C14nCanonicalization, C14nCanonicalizationWithComments } from "./c14n-canonicalization";
export {
  ExclusiveCanonicalization,
  ExclusiveCanonicalizationWithComments,
} from "./exclusive-canonicalization";
export { SignedXml } from "./signed-xml";
export * from "./types";

export { findAncestorNs, normalizePem, pemCertificates, pemToDer, toPem } from "./utils";

/*
 * `index.ts` used to re-export `./utils` wholesale, so helpers written for `signed-xml.ts` to
 * use were published too. They are being withdrawn in 7.0 (#551), and a name cannot simply
 * vanish without consumers having seen a warning first, so the ones on the removal list are
 * re-exported through `util.deprecate` here.
 *
 * The wrapping lives in this file rather than in `utils.ts` on purpose: siblings reach these
 * helpers as `utils.x`, which stays unwrapped, so no internal call path warns. Warning on our
 * own calls is what made #497 unpleasant.
 */

/**
 * @deprecated Will be removed in 7.0. This is an internal predicate with no replacement; use
 *   `Array.isArray(x) && x.length > 0`.
 */
export const isArrayHasLength = deprecate(
  utils.isArrayHasLength,
  "`isArrayHasLength()` is deprecated and will be removed in version 7.0. Use `Array.isArray(x) && x.length > 0` instead.",
  "XML_CRYPTO_IS_ARRAY_HAS_LENGTH",
);

/**
 * @deprecated Will be removed in 7.0. This is an internal DOM helper with no replacement; use a
 *   DOM API or the `xpath` package.
 */
export const findAttr = deprecate(
  utils.findAttr,
  "`findAttr()` is deprecated and will be removed in version 7.0. Use a DOM API or the `xpath` package instead.",
  "XML_CRYPTO_FIND_ATTR",
);

/**
 * @deprecated Will be removed in 7.0. This is an internal DOM helper with no replacement; use a
 *   DOM API or the `xpath` package.
 */
export const findChildren = deprecate(
  utils.findChildren,
  "`findChildren()` is deprecated and will be removed in version 7.0. Use a DOM API or the `xpath` package instead.",
  "XML_CRYPTO_FIND_CHILDREN",
);

/**
 * @deprecated Will be removed in 7.0. This is an internal DOM helper with no replacement; use a
 *   DOM API or the `xpath` package.
 */
export const findChilds = deprecate(
  /* eslint-disable-next-line deprecation/deprecation */
  utils.findChilds,
  "`findChilds()` is deprecated and will be removed in version 7.0. Use a DOM API or the `xpath` package instead.",
  "XML_CRYPTO_FIND_CHILDS",
);

/**
 * @deprecated Will be removed in 7.0. This is an internal DOM helper with no replacement;
 *   compare `parentNode` yourself, or use `Node.contains()` where the DOM provides it.
 */
export const isDescendantOf = deprecate(
  utils.isDescendantOf,
  "`isDescendantOf()` is deprecated and will be removed in version 7.0. Walk `parentNode` yourself, or use `Node.contains()` instead.",
  "XML_CRYPTO_IS_DESCENDANT_OF",
);

/**
 * @deprecated Will be removed in 7.0. This is the attribute-escaping step of this package's
 *   canonicalizers; use `C14nCanonicalization` or `ExclusiveCanonicalization` instead. A custom
 *   canonicalizer must apply C14N escaping itself: https://www.w3.org/TR/xml-c14n#ProcessingModel
 */
export const encodeSpecialCharactersInAttribute = deprecate(
  utils.encodeSpecialCharactersInAttribute,
  "`encodeSpecialCharactersInAttribute()` is deprecated and will be removed in version 7.0. Use `C14nCanonicalization` or `ExclusiveCanonicalization` instead.",
  "XML_CRYPTO_ENCODE_SPECIAL_CHARACTERS_IN_ATTRIBUTE",
);

/**
 * @deprecated Will be removed in 7.0. This is the text-escaping step of this package's
 *   canonicalizers; use `C14nCanonicalization` or `ExclusiveCanonicalization` instead. A custom
 *   canonicalizer must apply C14N escaping itself: https://www.w3.org/TR/xml-c14n#ProcessingModel
 */
export const encodeSpecialCharactersInText = deprecate(
  utils.encodeSpecialCharactersInText,
  "`encodeSpecialCharactersInText()` is deprecated and will be removed in version 7.0. Use `C14nCanonicalization` or `ExclusiveCanonicalization` instead.",
  "XML_CRYPTO_ENCODE_SPECIAL_CHARACTERS_IN_TEXT",
);

/**
 * @deprecated Will be removed in 7.0. Decode both digests from base64, then compare them with
 *   `a.length === b.length && crypto.timingSafeEqual(a, b)`: `timingSafeEqual` alone throws on a
 *   length mismatch instead of returning `false`. Do not compare them with `===`.
 */
export const validateDigestValue = deprecate(
  utils.validateDigestValue,
  "`validateDigestValue()` is deprecated and will be removed in version 7.0. Decode both digests from base64 and use `a.length === b.length && crypto.timingSafeEqual(a, b)` instead, and never `===`.",
  "XML_CRYPTO_VALIDATE_DIGEST_VALUE",
);

/**
 * @deprecated Will be removed in 7.0. Renamed to `toPem()`, which is what it has always done:
 *   its input is a PEM message, several of them, base64, or a Buffer of either PEM or DER.
 */
export const derToPem = deprecate(
  utils.toPem,
  "`derToPem()` is deprecated and will be removed in version 7.0. Use `toPem()` instead.",
  "XML_CRYPTO_DER_TO_PEM",
);

/*
 * The three regexes below cannot carry a runtime warning: `util.deprecate` wraps a function, and
 * a `RegExp` has no call to intercept. TypeScript consumers see the `@deprecated` tag; JavaScript
 * consumers get no signal until the name goes away in 7.0.
 *
 * They are defined here rather than in `utils.ts` because the parser no longer uses them. They
 * are frozen copies of what 6.1 exported, so that a consumer still reading them sees what it has
 * always seen until 7.0 removes them.
 */

/** @deprecated Will be removed in 7.0. This is an internal parsing detail with no replacement. */
export const PEM_FORMAT_REGEX = new RegExp(
  "^-----BEGIN [A-Z\x20]{1,48}-----([^-]*)-----END [A-Z\x20]{1,48}-----$",
  "s",
);

/** @deprecated Will be removed in 7.0. This is an internal parsing detail with no replacement. */
export const EXTRACT_X509_CERTS = new RegExp(
  "-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----",
  "g",
);

/** @deprecated Will be removed in 7.0. This is an internal parsing detail with no replacement. */
export const BASE64_REGEX = new RegExp(
  "^(?:[A-Za-z0-9\\+\\/]{4}\\n{0,1})*(?:[A-Za-z0-9\\+\\/]{2}==|[A-Za-z0-9\\+\\/]{3}=)?$",
  "s",
);
