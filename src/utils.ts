import { X509Certificate } from "crypto";
import * as xpath from "xpath";
import type { NamespacePrefix, PemLabel } from "./types";
import * as isDomNode from "@xmldom/is-dom-node";

export function isArrayHasLength(array: unknown): array is unknown[] {
  return Array.isArray(array) && array.length > 0;
}

function attrEqualsExplicitly(attr: Attr, localName: string, namespace?: string) {
  return attr.localName === localName && (attr.namespaceURI === namespace || namespace == null);
}

function attrEqualsImplicitly(attr: Attr, localName: string, namespace?: string, node?: Element) {
  return (
    attr.localName === localName &&
    ((!attr.namespaceURI && node?.namespaceURI === namespace) || namespace == null)
  );
}

export function findAttr(element: Element, localName: string, namespace?: string) {
  for (let i = 0; i < element.attributes.length; i++) {
    const attr = element.attributes[i];

    if (
      attrEqualsExplicitly(attr, localName, namespace) ||
      attrEqualsImplicitly(attr, localName, namespace, element)
    ) {
      return attr;
    }
  }
  return null;
}

export function findChildren(node: Node | Document, localName: string, namespace?: string) {
  const element = (node as Document).documentElement ?? node;
  const res: Element[] = [];
  for (let i = 0; i < element.childNodes.length; i++) {
    const child = element.childNodes[i];
    if (
      isDomNode.isElementNode(child) &&
      child.localName === localName &&
      (child.namespaceURI === namespace || namespace == null)
    ) {
      res.push(child);
    }
  }
  return res;
}

/**
 * @deprecated Will be removed in 7.0. This is an internal DOM helper with no replacement; use a
 *   DOM API or the `xpath` package.
 */
export function findChilds(node: Node | Document, localName: string, namespace?: string) {
  return findChildren(node, localName, namespace);
}

const xml_special_to_encoded_attribute = {
  "&": "&amp;",
  "<": "&lt;",
  '"': "&quot;",
  "\r": "&#xD;",
  "\n": "&#xA;",
  "\t": "&#x9;",
};

const xml_special_to_encoded_text = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  "\r": "&#xD;",
};

export function encodeSpecialCharactersInAttribute(attributeValue) {
  return attributeValue.replace(/([&<"\r\n\t])/g, function (str, item) {
    /** Special character normalization.
     * @see:
     * - https://www.w3.org/TR/xml-c14n#ProcessingModel (Attribute Nodes)
     * - https://www.w3.org/TR/xml-c14n#Example-Chars
     */
    return xml_special_to_encoded_attribute[item];
  });
}

export function encodeSpecialCharactersInText(text: string): string {
  return text.replace(/([&<>\r])/g, function (str, item) {
    /** Special character normalization.
     * @see:
     * - https://www.w3.org/TR/xml-c14n#ProcessingModel (Text Nodes)
     * - https://www.w3.org/TR/xml-c14n#Example-Chars
     */
    return xml_special_to_encoded_text[item];
  });
}

/*
 * RFC 7468 'textualmsg', with the deviations below.
 * https://www.rfc-editor.org/rfc/rfc7468
 *
 *  - line length is not enforced and several messages may be concatenated: section 2. Section 3
 *    lets a parser disregard the label of the post-encapsulation boundary, but this one requires
 *    the two to agree, because OpenSSL will not read a message whose labels disagree.
 *  - whitespace around the message is discarded, the '*W' of 'laxtextualmsg' in Figure 2, and a
 *    leading UTF-8 BOM with it.
 *  - blanks are discarded wherever they fall in the encapsulated data, not only at the ends of
 *    lines as Figure 1 permits, and base64 given without boundaries may hold a blank line as
 *    well. XMLDSig carries a certificate as xs:base64Binary, whose lexical space collapses
 *    whitespace, and a pretty-printed document indents it.
 *    https://www.w3.org/TR/xmlschema11-2/#base64Binary
 *  - a label is limited to 48 characters, which no registered label comes close to, so that an
 *    opening boundary still fits the line this module writes, and it may not be empty, which the
 *    'label' production of Figure 1 marks as 'empty ok'. A message labelled nothing names no
 *    format, and OpenSSL will not read one.
 *  - the header fields of RFC 1421 section 4.4 are read, which section 2 does not permit, but only
 *    the `Proc-Type` and `DEK-Info` that OpenSSL writes into a traditional encrypted private key,
 *    as Node exports one, so that a bundle may carry such a key beside its certificates. A message
 *    with them is not a certificate, and is neither rewritten nor decoded.
 *
 * Structure and data are separate checks, the data taken with its line breaks removed, so that a
 * line may end anywhere without `{4}` having to become the ambiguous `{1,4}`. Line endings and
 * blanks are normalized away rather than matched, because an 'eol' alternation inside a repeated
 * group backtracks exponentially and `[ \t]+` against an anchor is quadratic. Every pattern here
 * has to stay provably linear, which only an analyzer can establish and no timing test can:
 * `npx recheck@4 check '<source>' ''`.
 */

/*
 * Section 3 gives `labelchar = %x21-2C / %x2E-7E` and
 * `label = [ labelchar *( ["-" / SP] labelchar ) ]`. A separator is always followed by a label
 * character, so `--` can never occur inside a label and no boundary can be smuggled into one.
 * A label character is neither `-` nor a blank, which is what keeps the two disjoint and the
 * patterns below unambiguous.
 */
const LABEL_CHAR = "[\\x21-\\x2C\\x2E-\\x7E]";
const LABEL = `${LABEL_CHAR}(?:[-\\x20]?${LABEL_CHAR}){0,47}`;

/*
 * `-----BEGIN ` and `-----` bracket a label in 16 characters, so 48 is the longest label whose
 * opening boundary still fits the 64-character line `normalizePem` writes. The repetition above
 * bounds label characters alone, and the separators standing between them carry a label past 48
 * without exceeding it, so the length is measured rather than left to the pattern.
 */
const LABEL_MAX_LENGTH = 48;

const LABEL_REGEX = new RegExp(`^${LABEL}$`);
// A traditional encrypted private key opens with `Proc-Type` and `DEK-Info` fields and a blank
// line. Their values are held to what OpenSSL writes, blanks already removed, and so can never hold
// the `-----BEGIN ` of a boundary: a value that could would let the fields of one message run on
// over every message after it, which `recheck` reports as polynomial.
const HEADERS = "(?:(?:Proc-Type|DEK-Info):[A-Za-z0-9,-]+\\n)+\\n+";

const PEM_FORMAT_REGEX = new RegExp(
  `^(?:-----BEGIN ${LABEL}-----\\n+(?:${HEADERS})?(?:[A-Za-z0-9+/=]+\\n)+-----END ${LABEL}-----\\n*)+$`,
);
const PEM_MESSAGE_REGEX = new RegExp(
  `-----BEGIN (${LABEL})-----\\n+(${HEADERS})?((?:[A-Za-z0-9+/=]+\\n)+)-----END (${LABEL})-----`,
  "g",
);
// Base64 given without boundaries is what XMLDSig carries in `X509Certificate`, an
// `xs:base64Binary` whose lexical space collapses whitespace, so a blank line among its lines is
// insignificant and is taken here. Inside a message the body is RFC 7468's, which has no blank
// line in it, and `PEM_FORMAT_REGEX` holds that line to its own shape.
const BASE64_TEXT_REGEX = /^[A-Za-z0-9+/=\n]+$/;
const BASE64_DATA_REGEX = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

// A Buffer is decoded latin1 to keep every byte, which leaves a UTF-8 BOM as three characters
// rather than the U+FEFF that `trim()` would take, so both representations are removed here.
const BOM_REGEX = /^(?:\uFEFF|\u00EF\u00BB\u00BF)/;

function normalizePemInput(text: string): string {
  return text
    .replace(BOM_REGEX, "")
    .replace(/\r\n|\r/g, "\n")
    .split("\n")
    .map((line) => {
      const boundary = line.trim();
      // The blanks of a label are data, as in "RSA PUBLIC KEY"; those of an encoded line are not.
      return boundary.startsWith("-----") ? boundary : line.replace(/[ \t]+/g, "");
    })
    .join("\n")
    .trim();
}

interface PemMessage {
  label: string;
  endLabel: string;
  headers: boolean;
  data: string;
}

// Counted rather than matched, so that an opening boundary no message was built from is still
// seen, whatever left it unusable: a missing footer, a label too long to write back, or a body
// that is not base64. The blank of `-----BEGIN ` is left out deliberately, so that a boundary
// sharing its line with other text is counted here and refused, rather than passed over as prose
// and the certificate under it dropped from a signature without a word.
function countOpenings(text: string): number {
  return text.split("-----BEGIN").length - 1;
}

function pemMessages(pem: string): PemMessage[] {
  const messages: PemMessage[] = [];

  // Global regexes carry `lastIndex` between calls, so the loop runs to exhaustion to return it.
  PEM_MESSAGE_REGEX.lastIndex = 0;
  let message = PEM_MESSAGE_REGEX.exec(pem);
  while (message !== null) {
    const start = message.index;
    const end = start + message[0].length;

    // An encapsulation boundary is a line of its own in Figure 1, and a message is read out of a
    // larger value, so text sharing a boundary's line must not be passed over as the explanatory
    // text around the message. Anchoring that in the pattern costs it the linearity every pattern
    // here has to keep — `^` and `$` under `m` make it exponential, which `recheck` will say and
    // a timing test will not — so the position is taken from the match, where it is two tests.
    if ((start === 0 || pem[start - 1] === "\n") && (end === pem.length || pem[end] === "\n")) {
      messages.push({
        label: message[1],
        endLabel: message[4],
        headers: message[2] != null,
        // A line break inside base64 is presentation and never data, so where a line ends is a
        // question for the structure check alone, and the data is carried de-lined from here on.
        data: message[3].replace(/\n/g, ""),
      });
    }

    message = PEM_MESSAGE_REGEX.exec(pem);
  }

  // Every opening boundary has to have produced a message. One that did not is a message this
  // parser could not read — no footer, a label it will not write back, a body that is not base64,
  // or a boundary sharing its line — and passing over it would hand back a value with a
  // certificate or a key quietly missing from it. Held here so that no caller can omit it.
  if (countOpenings(pem) !== messages.length) {
    throw new Error("Invalid PEM format.");
  }

  return messages;
}

function isBase64Data(data: string): boolean {
  return BASE64_DATA_REGEX.test(data);
}

function isLabel(label: string): boolean {
  return label.length <= LABEL_MAX_LENGTH && LABEL_REGEX.test(label);
}

/*
 * A certificate is handed to Node, whose X509Certificate reads it as X.509 and not as base64
 * alone, so data that is well-formed base64 and no certificate is refused here rather than being
 * published in KeyInfo or failing later in Node's crypto. Node validates and does nothing more:
 * the octets are kept as given, because RFC 7468 section 5.1 allows BER, and XML Signature 1.1
 * says an implementation SHOULD NOT alter or re-encode a certificate, which could invalidate it.
 * https://www.w3.org/TR/xmldsig-core1/#sec-X509Data
 * What the parser above still owns is what Node does not do: finding each message in a value,
 * which X509Certificate answers by taking the first certificate and passing over the rest.
 */
function isX509Certificate(bytes: Buffer): boolean {
  try {
    new X509Certificate(bytes);
    return true;
  } catch {
    return false;
  }
}

function assertX509Certificate(data: string): void {
  const bytes = Buffer.from(data, "base64");

  if (!isX509Certificate(bytes)) {
    throw new Error("Invalid PEM format.");
  }

  // Node reads a certificate from the start of the bytes and passes over what follows it, which
  // 6.x did the same with. The data is exactly one certificate when dropping its last byte leaves
  // bytes Node cannot read, and that holds for DER and both forms of BER length alike, so no ASN.1
  // is parsed here. A crypto library that did not pass over what follows would refuse such data
  // above, and one that read a certificate cut short would refuse every certificate here: either
  // way what goes wrong is a refusal, never an acceptance.
  if (isX509Certificate(bytes.subarray(0, -1))) {
    throw new Error("Expected a single certificate, but found more data after it.");
  }
}

function isWellFormedMessage({ label, endLabel, headers, data }: PemMessage): boolean {
  // Header fields are what a traditional encrypted key carries, and a certificate never has them.
  const certificateWithHeaders = headers && label === "CERTIFICATE";

  return label === endLabel && isLabel(label) && isBase64Data(data) && !certificateWithHeaders;
}

// Base64 decodes to the same octets whatever its pad bits hold, but xs:base64Binary allows only
// zeros there, so data is written as the base64 of its octets and not as the text it arrived as.
// The octets themselves are untouched. https://www.w3.org/TR/xmlschema11-2/#base64Binary
function canonicalBase64(data: string): string {
  return Buffer.from(data, "base64").toString("base64");
}

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
 *  - split lines longer than 64 characters, leaving shorter ones as they are
 *  - ensure that 'preeb' has line ending '\n'
 *
 * @param pem The PEM string to normalize
 */
export function normalizePem(pem: string): string {
  return `${(
    pem
      .trim()
      .replace(/(\r\n|\r)/g, "\n")
      .match(/.{1,64}/g) ?? []
  ).join("\n")}\n`;
}

// Rebuilt from the data rather than passed through, so that the same certificate produces the
// same bytes whatever line width, line ending or blanks it arrived with. Only the data is handed
// to `normalizePem`, which wraps at 64 characters whatever it is given: a boundary broken across
// two lines would be a message this parser could no longer read back.
function formatPemMessage(label: string, data: string): string {
  if (label === "CERTIFICATE") {
    assertX509Certificate(data);
  }

  return `-----BEGIN ${label}-----\n${normalizePem(canonicalBase64(data))}-----END ${label}-----\n`;
}

/**
 * Returns the base64 data of each `CERTIFICATE` message in a PEM value, and `[]` when the value
 * holds no certificate: bare base64, or messages of other labels. Explanatory text before, after
 * or between the messages is passed over, as RFC 7468 section 5.2 allows, but every message the
 * value does hold is read and checked.
 *
 * @param pem The PEM value to read certificates from
 * @throws Error if the value opens a message it does not close as a well-formed PEM, or if a
 *   certificate's labels disagree or its data is not base64
 */
export function pemCertificates(pem: string): string[] {
  const text = normalizePemInput(pem);
  const messages = pemMessages(text);

  // Section 5.2 shows explanatory text before a certificate, and the tools that write one put the
  // subject and issuer there, so whatever surrounds a message is passed over rather than refused;
  // an opening boundary that produced no message is `pemMessages`' to refuse. Every message is
  // checked before any is filtered, because a message is a certificate by its opening label
  // alone, so one that opens as something else and closes as a certificate would be filtered away
  // unexamined, and signing would go on without the KeyInfo the caller asked for.
  if (!messages.every(isWellFormedMessage)) {
    throw new Error("Invalid PEM format.");
  }

  const certificates = messages
    .filter((message) => message.label === "CERTIFICATE")
    .map((certificate) => certificate.data);
  certificates.forEach(assertX509Certificate);

  return certificates.map(canonicalBase64);
}

/**
 * Returns the decoded bytes of the one PEM message a value holds, whatever its label.
 *
 * @param pem The PEM message to decode
 * @throws Error if the value is not a single well-formed PEM message
 */
export function pemToDer(pem: string): Buffer {
  const text = normalizePemInput(pem);
  const messages = PEM_FORMAT_REGEX.test(text) ? pemMessages(text) : [];

  if (messages.length > 1) {
    throw new Error(`Expected a single PEM message, but found ${messages.length}.`);
  }

  // A message with header fields holds a key encrypted under the cipher they name, and its bytes
  // are of no use without them.
  if (messages.length === 0 || !isWellFormedMessage(messages[0]) || messages[0].headers) {
    throw new Error("Invalid PEM format.");
  }

  const [{ label, data }] = messages;
  if (label === "CERTIFICATE") {
    assertX509Certificate(data);
  }

  return Buffer.from(data, "base64");
}

// A Buffer holds either the bytes of a PEM file or raw DER. DER is ASN.1, whose every encoding
// opens with a tag byte, never with the `-` of a boundary, so the two cannot be confused.
function pemText(value: string | Buffer): string {
  if (!Buffer.isBuffer(value)) {
    return value;
  }

  const text = value.toString("latin1");

  return text.replace(BOM_REGEX, "").trimStart().startsWith("-----BEGIN ")
    ? text
    : value.toString("base64");
}

// Refuses PEM rather than passing it through as toPem() does, so no key can come out as a certificate.
export function bareCertificate(value: string): string {
  const text = normalizePemInput(value);
  const data = text.replace(/\n/g, "");

  if (!BASE64_TEXT_REGEX.test(text) || !isBase64Data(data)) {
    throw new Error("Invalid PEM format.");
  }
  assertX509Certificate(data);

  return canonicalBase64(data);
}

/**
 * Returns a value as canonical PEM: one message per certificate or key, wrapped at 64 characters.
 * The value may be a PEM message, several of them, base64 data with the label supplied by the
 * caller, or a Buffer. A Buffer that opens with an encapsulation boundary is read as the bytes of
 * a PEM file and any other as raw DER, so base64 text is given as a string rather than a Buffer.
 *
 * @param value The certificate or key to return as PEM
 * @param pemLabel The label to give base64 data, which needs one; ignored when the value is PEM
 * @throws Error if the value is neither a well-formed PEM nor base64, or if it is base64 and no
 *   label, or an unusable one, was given
 */
export function toPem(value: string | Buffer, pemLabel?: PemLabel): string {
  const text = normalizePemInput(pemText(value));

  if (PEM_FORMAT_REGEX.test(text)) {
    const messages = pemMessages(text);
    // A message with header fields is read so that a bundle can carry one, but not rewritten: its
    // data is a key encrypted under the cipher they name, and written out without them it is lost.
    if (!messages.every(isWellFormedMessage) || messages.some((message) => message.headers)) {
      throw new Error("Invalid PEM format.");
    }

    return messages.map((message) => formatPemMessage(message.label, message.data)).join("");
  }

  const data = text.replace(/\n/g, "");

  if (BASE64_TEXT_REGEX.test(text) && isBase64Data(data)) {
    if (pemLabel == null) {
      throw new Error("A PEM label is required to wrap base64 data.");
    }

    // The label is written into both boundaries, so one that is not a label would produce a
    // message this parser could not read back, and `-----` in it would produce a second message.
    if (!isLabel(pemLabel)) {
      throw new Error("Invalid PEM label.");
    }

    return formatPemMessage(pemLabel, data);
  }

  throw new Error("Invalid PEM format.");
}

function collectAncestorNamespaces(
  node: Element,
  nsArray: NamespacePrefix[] = [],
): NamespacePrefix[] {
  if (!isDomNode.isElementNode(node.parentNode)) {
    return nsArray;
  }

  const parent: Element = node.parentNode;

  if (!parent) {
    return nsArray;
  }

  if (parent.attributes && parent.attributes.length > 0) {
    for (let i = 0; i < parent.attributes.length; i++) {
      const attr = parent.attributes[i];
      if (attr && attr.nodeName && attr.nodeName.search(/^xmlns:?/) !== -1) {
        nsArray.push({
          prefix: attr.nodeName.replace(/^xmlns:?/, ""),
          namespaceURI: attr.nodeValue || "",
        });
      }
    }
  }

  return collectAncestorNamespaces(parent, nsArray);
}

function findSubsetNSPrefixes(subset: Element): Set<string> {
  const prefixes = new Set<string>();
  const subsetAttributes = subset.attributes;
  for (let k = 0; k < subsetAttributes.length; k++) {
    const nodeName = subsetAttributes[k].nodeName;
    if (nodeName === "xmlns" || nodeName.startsWith("xmlns:")) {
      prefixes.add(nodeName.replace(/^xmlns:?/, ""));
    }
  }
  // C14N already renders the element's own namespace; hoisting it would duplicate the declaration.
  // https://www.w3.org/TR/2001/REC-xml-c14n-20010315#ProcessingModel
  prefixes.add(subset.prefix || "");
  return prefixes;
}

function isElementSubset(docSubset: Node[]): docSubset is Element[] {
  return docSubset.every((node) => isDomNode.isElementNode(node));
}

export function findAncestorNsForElement(node: Element): NamespacePrefix[] {
  const ancestorNs = collectAncestorNamespaces(node);
  const ancestorNsWithoutDuplicate: NamespacePrefix[] = [];
  for (const ns of ancestorNs) {
    const isDuplicate = ancestorNsWithoutDuplicate.some((seen) => seen.prefix === ns.prefix);
    if (!isDuplicate) {
      ancestorNsWithoutDuplicate.push(ns);
    }
  }

  const returningNs: NamespacePrefix[] = [];
  const subsetNsPrefixes = findSubsetNSPrefixes(node);
  for (const ancestorNs of ancestorNsWithoutDuplicate) {
    // An undeclaration has done its work by shadowing outer bindings; it is no namespace node.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#namespace-nodes
    const isUndeclaration = ancestorNs.namespaceURI === "";
    if (!isUndeclaration && !subsetNsPrefixes.has(ancestorNs.prefix)) {
      returningNs.push(ancestorNs);
    }
  }

  return returningNs;
}

/**
 * Extract ancestor namespaces in order to import it to root of document subset
 * which is being canonicalized for non-exclusive c14n.
 *
 * @param doc - Usually a product from `new xmldom.DOMParser().parseFromString()`
 * @param docSubsetXpath - xpath query to get document subset being canonicalized
 * @param namespaceResolver - xpath namespace resolver
 * @returns i.e. [{prefix: "saml", namespaceURI: "urn:oasis:names:tc:SAML:2.0:assertion"}]
 */
export function findAncestorNs(
  doc: Document,
  docSubsetXpath?: string,
  namespaceResolver?: XPathNSResolver,
): NamespacePrefix[] {
  if (docSubsetXpath == null) {
    return [];
  }

  const docSubset = xpath.selectWithResolver(docSubsetXpath, doc, namespaceResolver);

  if (!isArrayHasLength(docSubset)) {
    return [];
  }

  if (!isElementSubset(docSubset)) {
    throw new Error("Document subset must be list of elements");
  }

  return findAncestorNsForElement(docSubset[0]);
}

export function isPrefixInScope(
  prefixesInScope: NamespacePrefix[],
  prefix: string,
  namespaceURI: string,
): boolean {
  // Bindings are pushed outermost first, so the last one for a prefix shadows the rest.
  const binding = prefixesInScope.filter((ns) => ns.prefix === prefix).pop();
  return binding !== undefined && binding.namespaceURI === namespaceURI;
}

export function validateDigestValue(digest, expectedDigest) {
  const buffer = Buffer.from(digest, "base64");
  const expectedBuffer = Buffer.from(expectedDigest, "base64");

  if (typeof buffer.equals === "function") {
    return buffer.equals(expectedBuffer);
  }

  if (buffer.length !== expectedBuffer.length) {
    return false;
  }

  for (let i = 0; i < buffer.length; i++) {
    if (buffer[i] !== expectedBuffer[i]) {
      return false;
    }
  }

  return true;
}

// Check if the given node is descendant of the given parent node
export function isDescendantOf(node: Node, parent: Node): boolean {
  if (!node || !parent) {
    return false;
  }

  let currentNode: Node | null = node.parentNode;

  while (currentNode) {
    if (currentNode === parent) {
      return true;
    }
    currentNode = currentNode.parentNode;
  }

  return false;
}
