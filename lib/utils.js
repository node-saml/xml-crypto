const xpath = require("xpath");

function attrEqualsExplicitly(attr, localName, namespace) {
  return attr.localName === localName && (attr.namespaceURI === namespace || !namespace);
}

function attrEqualsImplicitly(attr, localName, namespace, node) {
  return (
    attr.localName === localName &&
    ((!attr.namespaceURI && node.namespaceURI === namespace) || !namespace)
  );
}

function findAttr(node, localName, namespace) {
  for (let i = 0; i < node.attributes.length; i++) {
    const attr = node.attributes[i];

    if (
      attrEqualsExplicitly(attr, localName, namespace) ||
      attrEqualsImplicitly(attr, localName, namespace, node)
    ) {
      return attr;
    }
  }
  return null;
}

function findFirst(doc, path) {
  const nodes = xpath.select(path, doc);
  if (nodes.length === 0) {
    throw "could not find xpath " + path;
  }
  return nodes[0];
}

function findChilds(node, localName, namespace) {
  node = node.documentElement || node;
  const res = [];
  for (let i = 0; i < node.childNodes.length; i++) {
    const child = node.childNodes[i];
    if (child.localName === localName && (child.namespaceURI === namespace || !namespace)) {
      res.push(child);
    }
  }
  return res;
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

function encodeSpecialCharactersInAttribute(attributeValue) {
  return attributeValue.replace(/([&<"\r\n\t])/g, function (str, item) {
    // Special character normalization. See:
    // - https://www.w3.org/TR/xml-c14n#ProcessingModel (Attribute Nodes)
    // - https://www.w3.org/TR/xml-c14n#Example-Chars
    return xml_special_to_encoded_attribute[item];
  });
}

function encodeSpecialCharactersInText(text) {
  return text.replace(/([&<>\r])/g, function (str, item) {
    // Special character normalization. See:
    // - https://www.w3.org/TR/xml-c14n#ProcessingModel (Text Nodes)
    // - https://www.w3.org/TR/xml-c14n#Example-Chars
    return xml_special_to_encoded_text[item];
  });
}

const EXTRACT_X509_CERTS = new RegExp(
  "-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----",
  "g"
);
const PEM_FORMAT_REGEX = new RegExp(
  "^-----BEGIN [A-Z\x20]{1,48}-----([^-]*)-----END [A-Z\x20]{1,48}-----$",
  "s"
);
const BASE64_REGEX = new RegExp(
  "^(?:[A-Za-z0-9\\+\\/]{4}\\n{0,1})*(?:[A-Za-z0-9\\+\\/]{2}==|[A-Za-z0-9\\+\\/]{3}=)?$",
  "s"
);

function normalizePem(pem) {
  return `${(
    pem
      .trim()
      .replace(/(\r\n|\r)/g, "\n")
      .match(/.{1,64}/g) ?? []
  ).join("\n")}\n`;
}

function pemToDer(pem) {
  return pem
    .replace(/(\r\n|\r)/g, "\n")
    .replace(/-----BEGIN [A-Z\x20]{1,48}-----\n?/, "")
    .replace(/-----END [A-Z\x20]{1,48}-----\n?/, "");
}

function derToPem(der, pemLabel) {
  const base64Der = Buffer.isBuffer(der) ? der.toString("latin1").trim() : der.trim();

  if (PEM_FORMAT_REGEX.test(base64Der)) {
    return normalizePem(base64Der);
  }

  if (BASE64_REGEX.test(base64Der)) {
    const pem = `-----BEGIN ${pemLabel}-----\n${base64Der}\n-----END ${pemLabel}-----`;

    return normalizePem(pem);
  }

  throw new Error("Unknown DER format.");
}

function collectAncestorNamespaces(node, nsArray) {
  if (!nsArray) {
    nsArray = [];
  }

  const parent = node.parentNode;

  if (!parent) {
    return nsArray;
  }

  if (parent.attributes && parent.attributes.length > 0) {
    for (let i = 0; i < parent.attributes.length; i++) {
      const attr = parent.attributes[i];
      if (attr && attr.nodeName && attr.nodeName.search(/^xmlns:?/) !== -1) {
        nsArray.push({
          prefix: attr.nodeName.replace(/^xmlns:?/, ""),
          namespaceURI: attr.nodeValue,
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

/**
 * Extract ancestor namespaces in order to import it to root of document subset
 * which is being canonicalized for non-exclusive c14n.
 *
 * @param {object} doc - Usually a product from `new DOMParser().parseFromString()`
 * @param {string} docSubsetXpath - xpath query to get document subset being canonicalized
 * @param {object} namespaceResolver - xpath namespace resolver
 * @returns {Array} i.e. [{prefix: "saml", namespaceURI: "urn:oasis:names:tc:SAML:2.0:assertion"}]
 */
function findAncestorNs(doc, docSubsetXpath, namespaceResolver) {
  const docSubset = xpath.selectWithResolver(docSubsetXpath, doc, namespaceResolver);

  if (!Array.isArray(docSubset) || docSubset.length < 1) {
    return [];
  }

  // Remove duplicate on ancestor namespace
  const ancestorNs = collectAncestorNamespaces(docSubset[0]);
  const ancestorNsWithoutDuplicate = [];
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
  const returningNs = [];
  const subsetNsPrefix = findNSPrefix(docSubset[0]);
  for (const ancestorNs of ancestorNsWithoutDuplicate) {
    if (ancestorNs.prefix !== subsetNsPrefix) {
      returningNs.push(ancestorNs);
    }
  }

  return returningNs;
}

function validateDigestValue(digest, expectedDigest) {
  let buffer;
  let expectedBuffer;

  const majorVersion = /^v(\d+)/.exec(process.version)[1];

  if (+majorVersion >= 6) {
    buffer = Buffer.from(digest, "base64");
    expectedBuffer = Buffer.from(expectedDigest, "base64");
  } else {
    // Compatibility with Node < 5.10.0
    buffer = new Buffer(digest, "base64");
    expectedBuffer = new Buffer(expectedDigest, "base64");
  }

  if (typeof buffer.equals === "function") {
    return buffer.equals(expectedBuffer);
  }

  // Compatibility with Node < 0.11.13
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

module.exports = {
  findAttr,
  findChilds,
  encodeSpecialCharactersInAttribute,
  encodeSpecialCharactersInText,
  findFirst,
  EXTRACT_X509_CERTS,
  PEM_FORMAT_REGEX,
  BASE64_REGEX,
  pemToDer,
  derToPem,
  normalizePem,
  collectAncestorNamespaces,
  findAncestorNs,
  validateDigestValue,
};
