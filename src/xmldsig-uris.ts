/**
 * Supported canonicalization algorithms
 */
const CANONICALIZATION_ALGORITHMS = {
  C14N: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
  C14N_WITH_COMMENTS: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
  EXCLUSIVE_C14N: "http://www.w3.org/2001/10/xml-exc-c14n#",
  EXCLUSIVE_C14N_WITH_COMMENTS: "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
} as const;

/**
 * Supported transform algorithms (includes canonicalization + enveloped signature)
 */
const TRANSFORM_ALGORITHMS = {
  ...CANONICALIZATION_ALGORITHMS,
  ENVELOPED_SIGNATURE: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
} as const;

/**
 * Supported digest algorithms
 */
const HASH_ALGORITHMS = {
  SHA1: "http://www.w3.org/2000/09/xmldsig#sha1",
  SHA256: "http://www.w3.org/2001/04/xmlenc#sha256",
  SHA512: "http://www.w3.org/2001/04/xmlenc#sha512",
} as const;

/**
 * Supported signature algorithms
 */
const SIGNATURE_ALGORITHMS = {
  RSA_SHA1: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
  RSA_SHA256: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  RSA_SHA256_MGF1: "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1",
  RSA_SHA512: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
  HMAC_SHA1: "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
} as const;

/**
 * Common XML namespaces
 */
const NAMESPACES = {
  xml: "http://www.w3.org/XML/1998/namespace",
  xmlns: "http://www.w3.org/2000/xmlns/",
  ds: "http://www.w3.org/2000/09/xmldsig#",
  wsu: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
  wsse: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
  xades: "http://uri.etsi.org/01903/v1.3.2#",
} as const;

/**
 * XML-DSig URI constants organized by category
 */
export const XMLDSIG_URIS = {
  CANONICALIZATION_ALGORITHMS,
  TRANSFORM_ALGORITHMS,
  HASH_ALGORITHMS,
  SIGNATURE_ALGORITHMS,
  NAMESPACES,
} as const;
