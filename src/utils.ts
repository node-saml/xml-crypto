import * as xpath from "xpath";
import type { NamespacePrefix } from "./types";
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
 *    lines as Figure 1 permits. XMLDSig carries a certificate as xs:base64Binary, whose lexical
 *    space allows whitespace, and a pretty-printed document indents it.
 *    https://www.w3.org/TR/xmlschema11-2/#base64Binary
 *
 * Structure and data are separate checks, the data taken with its line breaks removed, so that a
 * line may end anywhere without `{4}` having to become the ambiguous `{1,4}`. Line endings and
 * blanks are normalized away rather than matched, because an 'eol' alternation inside a repeated
 * group backtracks exponentially and `[ \t]+` against an anchor is quadratic. Every pattern here
 * has to stay provably linear, which only an analyzer can establish and no timing test can:
 * `npx recheck@4 check '<source>' ''`.
 */
const PEM_FORMAT_REGEX =
  /^(?:-----BEGIN [A-Z\x20]{1,48}-----\n+(?:[A-Za-z0-9+/=]+\n)+-----END [A-Z\x20]{1,48}-----\n*)+$/;
const PEM_MESSAGE_REGEX =
  /-----BEGIN ([A-Z\x20]{1,48})-----\n+((?:[A-Za-z0-9+/=]+\n)+)-----END ([A-Z\x20]{1,48})-----/g;
const BASE64_LINES_REGEX = /^(?:[A-Za-z0-9+/=]+\n)*[A-Za-z0-9+/=]+$/;
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
  data: string;
}

function pemMessages(pem: string): PemMessage[] {
  const messages: PemMessage[] = [];

  // Global regexes carry `lastIndex` between calls, so the loop runs to exhaustion to return it.
  PEM_MESSAGE_REGEX.lastIndex = 0;
  let message = PEM_MESSAGE_REGEX.exec(pem);
  while (message !== null) {
    messages.push({
      label: message[1],
      endLabel: message[3],
      // A line break inside base64 is presentation and never data, so where a line ends is a
      // question for the structure check alone, and the data is carried de-lined from here on.
      data: message[2].replace(/\n/g, ""),
    });
    message = PEM_MESSAGE_REGEX.exec(pem);
  }

  return messages;
}

function isBase64Data(data: string): boolean {
  return BASE64_DATA_REGEX.test(data);
}

function isWellFormedMessage({ label, endLabel, data }: PemMessage): boolean {
  return label === endLabel && isBase64Data(data);
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
// same bytes whatever line width, line ending or blanks it arrived with.
function formatPemMessage(label: string, data: string): string {
  return normalizePem(`-----BEGIN ${label}-----\n${data}\n-----END ${label}-----`);
}

/**
 * Returns the base64 data of each `CERTIFICATE` message in a PEM value, and `[]` when the value
 * holds no certificate: bare base64, or messages of other labels.
 *
 * @param pem The PEM value to read certificates from
 * @throws Error if the value opens a message it does not close as a well-formed PEM, or if a
 *   certificate's labels disagree or its data is not base64
 */
export function pemCertificates(pem: string): string[] {
  const text = normalizePemInput(pem);

  if (!PEM_FORMAT_REGEX.test(text)) {
    // A value with no boundaries at all holds no certificate to publish, but one that opens a
    // message it cannot finish is a certificate we failed to read, and dropping it would sign
    // without the KeyInfo the caller asked for.
    if (text.includes("-----BEGIN ")) {
      throw new Error("Invalid PEM format.");
    }

    return [];
  }

  const certificates = pemMessages(text).filter((message) => message.label === "CERTIFICATE");
  if (!certificates.every(isWellFormedMessage)) {
    throw new Error("Invalid PEM format.");
  }

  return certificates.map((certificate) => certificate.data);
}

/**
 * @param pem The PEM-encoded base64 certificate to strip headers from
 * @throws Error if the value is not a single well-formed PEM message
 */
export function pemToDer(pem: string): Buffer {
  const text = normalizePemInput(pem);
  const messages = PEM_FORMAT_REGEX.test(text) ? pemMessages(text) : [];

  if (messages.length > 1) {
    throw new Error(`Expected a single PEM message, but found ${messages.length}.`);
  }

  if (messages.length === 0 || !isWellFormedMessage(messages[0])) {
    throw new Error("Invalid PEM format.");
  }

  return Buffer.from(messages[0].data, "base64");
}

/**
 * @param der The DER-encoded base64 certificate to add PEM headers too
 * @param pemLabel The label of the header and footer to add
 * @throws Error if the value is neither a well-formed PEM nor base64, or if it is base64 and no
 *   label was given
 */
export function derToPem(
  der: string | Buffer,
  pemLabel?: "CERTIFICATE" | "PRIVATE KEY" | "RSA PUBLIC KEY",
): string {
  const text = normalizePemInput(Buffer.isBuffer(der) ? der.toString("base64") : der);

  if (PEM_FORMAT_REGEX.test(text)) {
    const messages = pemMessages(text);
    if (!messages.every(isWellFormedMessage)) {
      throw new Error("Unknown DER format.");
    }

    return messages.map((message) => formatPemMessage(message.label, message.data)).join("");
  }

  const data = text.replace(/\n/g, "");

  if (BASE64_LINES_REGEX.test(text) && isBase64Data(data)) {
    if (pemLabel == null) {
      throw new Error("PEM label is required when DER is given.");
    }

    return formatPemMessage(pemLabel, data);
  }

  throw new Error("Unknown DER format.");
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
    if (!subsetNsPrefixes.has(ancestorNs.prefix)) {
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
