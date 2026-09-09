import { deprecate } from "util";
import * as utils from "./utils";

export { C14nCanonicalization, C14nCanonicalizationWithComments } from "./c14n-canonicalization";
export {
  ExclusiveCanonicalization,
  ExclusiveCanonicalizationWithComments,
} from "./exclusive-canonicalization";
export { SignedXml } from "./signed-xml";
export * from "./types";

export { derToPem, findAncestorNs, normalizePem, pemToDer } from "./utils";

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
 * @deprecated Will be removed in 7.0. Use {@link findChildren} instead; the signature and
 *   behaviour are identical.
 */
export const findChilds = deprecate(
  /* eslint-disable-next-line deprecation/deprecation */
  utils.findChilds,
  "`findChilds()` is deprecated and will be removed in version 7.0. Use `findChildren()` instead.",
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
 * @deprecated Will be removed in 7.0. This implements c14n special-character normalization for
 *   this package; an XML serializer escapes attribute values for you.
 */
export const encodeSpecialCharactersInAttribute = deprecate(
  utils.encodeSpecialCharactersInAttribute,
  "`encodeSpecialCharactersInAttribute()` is deprecated and will be removed in version 7.0. Use an XML serializer instead.",
  "XML_CRYPTO_ENCODE_SPECIAL_CHARACTERS_IN_ATTRIBUTE",
);

/**
 * @deprecated Will be removed in 7.0. This implements c14n special-character normalization for
 *   this package; an XML serializer escapes text content for you.
 */
export const encodeSpecialCharactersInText = deprecate(
  utils.encodeSpecialCharactersInText,
  "`encodeSpecialCharactersInText()` is deprecated and will be removed in version 7.0. Use an XML serializer instead.",
  "XML_CRYPTO_ENCODE_SPECIAL_CHARACTERS_IN_TEXT",
);

/**
 * @deprecated Will be removed in 7.0. Compare digests with
 *   `crypto.timingSafeEqual(Buffer.from(a, "base64"), Buffer.from(b, "base64"))`, which throws
 *   on a length mismatch — that counts as unequal. Do not compare them with `===`.
 */
export const validateDigestValue = deprecate(
  utils.validateDigestValue,
  '`validateDigestValue()` is deprecated and will be removed in version 7.0. Use `crypto.timingSafeEqual(Buffer.from(a, "base64"), Buffer.from(b, "base64"))` instead, and never `===`.',
  "XML_CRYPTO_VALIDATE_DIGEST_VALUE",
);

/*
 * The three regexes below cannot carry a runtime warning: `util.deprecate` wraps a function, and
 * a `RegExp` has no call to intercept. TypeScript consumers see the `@deprecated` tag; JavaScript
 * consumers get no signal until the name goes away in 7.0.
 */

/** @deprecated Will be removed in 7.0. This is an internal parsing detail with no replacement. */
export const PEM_FORMAT_REGEX = utils.PEM_FORMAT_REGEX;

/** @deprecated Will be removed in 7.0. This is an internal parsing detail with no replacement. */
export const EXTRACT_X509_CERTS = utils.EXTRACT_X509_CERTS;

/** @deprecated Will be removed in 7.0. This is an internal parsing detail with no replacement. */
export const BASE64_REGEX = utils.BASE64_REGEX;
