/* jshint laxcomma: true */
const utils = require("./utils");

class C14nCanonicalization {
  constructor() {
    this.includeComments = false;
  }

  attrCompare(a, b) {
    if (!a.namespaceURI && b.namespaceURI) {
      return -1;
    }
    if (!b.namespaceURI && a.namespaceURI) {
      return 1;
    }

    const left = a.namespaceURI + a.localName;
    const right = b.namespaceURI + b.localName;

    if (left === right) {
      return 0;
    } else if (left < right) {
      return -1;
    } else {
      return 1;
    }
  }

  nsCompare(a, b) {
    const attr1 = a.prefix;
    const attr2 = b.prefix;
    if (attr1 == attr2) {
      return 0;
    }
    return attr1.localeCompare(attr2);
  }

  renderAttrs(node, defaultNS) {
    let a;
    let i;
    let attr;
    const res = [];
    const attrListToRender = [];

    if (node.nodeType === 8) {
      return this.renderComment(node);
    }

    if (node.attributes) {
      for (i = 0; i < node.attributes.length; ++i) {
        attr = node.attributes[i];
        //ignore namespace definition attributes
        if (attr.name.indexOf("xmlns") === 0) {
          continue;
        }
        attrListToRender.push(attr);
      }
    }

    attrListToRender.sort(this.attrCompare);

    for (a in attrListToRender) {
      if (!attrListToRender.hasOwnProperty(a)) {
        continue;
      }

      attr = attrListToRender[a];
      res.push(" ", attr.name, '="', utils.encodeSpecialCharactersInAttribute(attr.value), '"');
    }

    return res.join("");
  }

  /**
   * Create the string of all namespace declarations that should appear on this element
   *
   * @param {Node} node. The node we now render
   * @param {Array} prefixesInScope. The prefixes defined on this node
   *                parents which are a part of the output set
   * @param {String} defaultNs. The current default namespace
   * @param {String} defaultNsForPrefix.
   * @param {String} ancestorNamespaces - Import ancestor namespaces if it is specified
   * @return {String}
   * @api private
   */
  renderNs(node, prefixesInScope, defaultNs, defaultNsForPrefix, ancestorNamespaces) {
    let a;
    let i;
    let p;
    let attr;
    const res = [];
    let newDefaultNs = defaultNs;
    const nsListToRender = [];
    const currNs = node.namespaceURI || "";

    //handle the namespaceof the node itself
    if (node.prefix) {
      if (prefixesInScope.indexOf(node.prefix) == -1) {
        nsListToRender.push({
          prefix: node.prefix,
          namespaceURI: node.namespaceURI || defaultNsForPrefix[node.prefix],
        });
        prefixesInScope.push(node.prefix);
      }
    } else if (defaultNs != currNs) {
      //new default ns
      newDefaultNs = node.namespaceURI;
      res.push(' xmlns="', newDefaultNs, '"');
    }

    //handle the attributes namespace
    if (node.attributes) {
      for (i = 0; i < node.attributes.length; ++i) {
        attr = node.attributes[i];

        //handle all prefixed attributes that are included in the prefix list and where
        //the prefix is not defined already. New prefixes can only be defined by `xmlns:`.
        if (attr.prefix === "xmlns" && prefixesInScope.indexOf(attr.localName) === -1) {
          nsListToRender.push({ prefix: attr.localName, namespaceURI: attr.value });
          prefixesInScope.push(attr.localName);
        }

        //handle all prefixed attributes that are not xmlns definitions and where
        //the prefix is not defined already
        if (
          attr.prefix &&
          prefixesInScope.indexOf(attr.prefix) == -1 &&
          attr.prefix != "xmlns" &&
          attr.prefix != "xml"
        ) {
          nsListToRender.push({ prefix: attr.prefix, namespaceURI: attr.namespaceURI });
          prefixesInScope.push(attr.prefix);
        }
      }
    }

    if (Array.isArray(ancestorNamespaces) && ancestorNamespaces.length > 0) {
      // Remove namespaces which are already present in nsListToRender
      for (const p1 in ancestorNamespaces) {
        if (!ancestorNamespaces.hasOwnProperty(p1)) {
          continue;
        }
        let alreadyListed = false;
        for (const p2 in nsListToRender) {
          if (
            nsListToRender[p2].prefix === ancestorNamespaces[p1].prefix &&
            nsListToRender[p2].namespaceURI === ancestorNamespaces[p1].namespaceURI
          ) {
            alreadyListed = true;
          }
        }

        if (!alreadyListed) {
          nsListToRender.push(ancestorNamespaces[p1]);
        }
      }
    }

    nsListToRender.sort(this.nsCompare);

    //render namespaces
    for (a in nsListToRender) {
      if (!nsListToRender.hasOwnProperty(a)) {
        continue;
      }

      p = nsListToRender[a];
      res.push(" xmlns:", p.prefix, '="', p.namespaceURI, '"');
    }

    return { rendered: res.join(""), newDefaultNs: newDefaultNs };
  }

  processInner(node, prefixesInScope, defaultNs, defaultNsForPrefix, ancestorNamespaces) {
    if (node.nodeType === 8) {
      return this.renderComment(node);
    }
    if (node.data) {
      return utils.encodeSpecialCharactersInText(node.data);
    }

    let i;
    let pfxCopy;
    const ns = this.renderNs(
      node,
      prefixesInScope,
      defaultNs,
      defaultNsForPrefix,
      ancestorNamespaces
    );
    const res = ["<", node.tagName, ns.rendered, this.renderAttrs(node, ns.newDefaultNs), ">"];

    for (i = 0; i < node.childNodes.length; ++i) {
      pfxCopy = prefixesInScope.slice(0);
      res.push(
        this.processInner(node.childNodes[i], pfxCopy, ns.newDefaultNs, defaultNsForPrefix, [])
      );
    }

    res.push("</", node.tagName, ">");
    return res.join("");
  }

  // Thanks to deoxxa/xml-c14n for comment renderer
  renderComment(node) {
    if (!this.includeComments) {
      return "";
    }

    const isOutsideDocument = node.ownerDocument === node.parentNode;
    let isBeforeDocument = null;
    let isAfterDocument = null;

    if (isOutsideDocument) {
      let nextNode = node;
      let previousNode = node;

      while (nextNode !== null) {
        if (nextNode === node.ownerDocument.documentElement) {
          isBeforeDocument = true;
          break;
        }

        nextNode = nextNode.nextSibling;
      }

      while (previousNode !== null) {
        if (previousNode === node.ownerDocument.documentElement) {
          isAfterDocument = true;
          break;
        }

        previousNode = previousNode.previousSibling;
      }
    }

    return (
      (isAfterDocument ? "\n" : "") +
      "<!--" +
      utils.encodeSpecialCharactersInText(node.data) +
      "-->" +
      (isBeforeDocument ? "\n" : "")
    );
  }

  /**
   * Perform canonicalization of the given node
   *
   * @param {Node} node
   * @return {String}
   * @api public
   */
  process(node, options) {
    options = options || {};
    const defaultNs = options.defaultNs || "";
    const defaultNsForPrefix = options.defaultNsForPrefix || {};
    const ancestorNamespaces = options.ancestorNamespaces || [];

    const prefixesInScope = [];
    for (let i = 0; i < ancestorNamespaces.length; i++) {
      prefixesInScope.push(ancestorNamespaces[i].prefix);
    }

    const res = this.processInner(
      node,
      prefixesInScope,
      defaultNs,
      defaultNsForPrefix,
      ancestorNamespaces
    );
    return res;
  }

  getAlgorithmName() {
    return "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
  }
}

// Add c14n#WithComments here (very simple subclass)
class C14nCanonicalizationWithComments extends C14nCanonicalization {
  constructor() {
    super();
    this.includeComments = true;
  }

  getAlgorithmName() {
    return "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
  }
}

module.exports = {
  C14nCanonicalization,
  C14nCanonicalizationWithComments,
};
