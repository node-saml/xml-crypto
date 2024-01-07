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

/** @deprecated */
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
export const PEM_FORMAT_REGEX = new RegExp(
  "^-----BEGIN [A-Z\x20]{1,48}-----([^-]*)-----END [A-Z\x20]{1,48}-----$",
  "s",
);
export const EXTRACT_X509_CERTS = new RegExp(
  "-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----",
  "g",
);
export const BASE64_REGEX = new RegExp(
  "^(?:[A-Za-z0-9\\+\\/]{4}\\n{0,1})*(?:[A-Za-z0-9\\+\\/]{2}==|[A-Za-z0-9\\+\\/]{3}=)?$",
  "s",
);

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
 * With a couple of notes:
 *  - 'eol' is normalized to '\n'
 *
 * @param pem The PEM string to normalize to RFC7468 'stricttextualmsg' definition
 */
export function normalizePem(pem: string): string {
  return `${(
    pem
      .trim()
      .replace(/(\r\n|\r)/g, "\n")
      .match(/.{1,64}/g) ?? []
  ).join("\n")}\n`;
}

/**
 * @param pem The PEM-encoded base64 certificate to strip headers from
 */
export function pemToDer(pem: string): Buffer {
  if (!PEM_FORMAT_REGEX.test(pem.trim())) {
    throw new Error("Invalid PEM format.");
  }

  return Buffer.from(
    pem
      .replace(/(\r\n|\r)/g, "")
      .replace(/-----BEGIN [A-Z\x20]{1,48}-----\n?/, "")
      .replace(/-----END [A-Z\x20]{1,48}-----\n?/, ""),
    "base64",
  );
}

/**
 * @param der The DER-encoded base64 certificate to add PEM headers too
 * @param pemLabel The label of the header and footer to add
 */
export function derToPem(
  der: string | Buffer,
  pemLabel?: "CERTIFICATE" | "PRIVATE KEY" | "RSA PUBLIC KEY",
): string {
  const base64Der = Buffer.isBuffer(der)
    ? der.toString("base64").trim()
    : der.replace(/(\r\n|\r)/g, "").trim();

  if (PEM_FORMAT_REGEX.test(base64Der)) {
    return normalizePem(base64Der);
  }

  if (BASE64_REGEX.test(base64Der.replace(/ /g, ""))) {
    if (pemLabel == null) {
      throw new Error("PEM label is required when DER is given.");
    }
    const pem = `-----BEGIN ${pemLabel}-----\n${base64Der.replace(
      / /g,
      "",
    )}\n-----END ${pemLabel}-----`;

    return normalizePem(pem);
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

function findNSPrefix(subset) {
  const subsetAttributes = subset.attributes;
  for (let k = 0; k < subsetAttributes.length; k++) {
    const nodeName = subsetAttributes[k].nodeName;
    if (nodeName.search(/^xmlns:?/) !== -1) {
      return nodeName.replace(/^xmlns:?/, "");
    }
  }
  return subset.prefix || "";
}

function isElementSubset(docSubset: Node[]): docSubset is Element[] {
  return docSubset.every((node) => isDomNode.isElementNode(node));
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

  // Remove duplicate on ancestor namespace
  const ancestorNs = collectAncestorNamespaces(docSubset[0]);
  const ancestorNsWithoutDuplicate: NamespacePrefix[] = [];
  for (let i = 0; i < ancestorNs.length; i++) {
    let notOnTheList = true;
    for (const v in ancestorNsWithoutDuplicate) {
      if (ancestorNsWithoutDuplicate[v].prefix === ancestorNs[i].prefix) {
        notOnTheList = false;
        break;
      }
    }

    if (notOnTheList) {
      ancestorNsWithoutDuplicate.push(ancestorNs[i]);
    }
  }

  // Remove namespaces which are already declared in the subset with the same prefix
  const returningNs: NamespacePrefix[] = [];
  const subsetNsPrefix = findNSPrefix(docSubset[0]);
  for (const ancestorNs of ancestorNsWithoutDuplicate) {
    if (ancestorNs.prefix !== subsetNsPrefix) {
      returningNs.push(ancestorNs);
    }
  }

  return returningNs;
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
