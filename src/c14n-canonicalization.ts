import type {
  CanonicalizationOrTransformationAlgorithm,
  CanonicalizationOrTransformationAlgorithmProcessOptions,
  NamespacePrefix,
  RenderedNamespace,
} from "./types";
import * as utils from "./utils";
import * as isDomNode from "@xmldom/is-dom-node";

export class C14nCanonicalization implements CanonicalizationOrTransformationAlgorithm {
  protected includeComments = false;

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
    if (attr1 === attr2) {
      return 0;
    }
    return attr1.localeCompare(attr2);
  }

  renderAttrs(node) {
    let i;
    let attr;
    const attrListToRender: Attr[] = [];

    if (isDomNode.isCommentNode(node)) {
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

    const res = attrListToRender.map((attr) => {
      return ` ${attr.name}="${utils.encodeSpecialCharactersInAttribute(attr.value)}"`;
    });

    return res.join("");
  }

  /**
   * Create the string of all namespace declarations that should appear on this element
   *
   * @param node The node we now render
   * @param prefixesInScope The prefixes defined on this node parents which are a part of the output set
   * @param defaultNs The current default namespace
   * @param defaultNsForPrefix
   * @param ancestorNamespaces Import ancestor namespaces if it is specified
   * @api private
   */
  renderNs(
    node: Element,
    prefixesInScope: string[],
    defaultNs: string,
    defaultNsForPrefix: string,
    ancestorNamespaces: NamespacePrefix[],
  ): RenderedNamespace {
    let i;
    let attr;
    const res: string[] = [];
    let newDefaultNs = defaultNs;
    const nsListToRender: { prefix: string; namespaceURI: string }[] = [];
    const currNs = node.namespaceURI || "";

    //handle the namespace of the node itself
    if (node.prefix) {
      if (prefixesInScope.indexOf(node.prefix) === -1) {
        nsListToRender.push({
          prefix: node.prefix,
          namespaceURI: node.namespaceURI || defaultNsForPrefix[node.prefix],
        });
        prefixesInScope.push(node.prefix);
      }
    } else if (defaultNs !== currNs) {
      //new default ns
      newDefaultNs = node.namespaceURI || "";
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
          prefixesInScope.indexOf(attr.prefix) === -1 &&
          attr.prefix !== "xmlns" &&
          attr.prefix !== "xml"
        ) {
          nsListToRender.push({ prefix: attr.prefix, namespaceURI: attr.namespaceURI });
          prefixesInScope.push(attr.prefix);
        }
      }
    }

    if (utils.isArrayHasLength(ancestorNamespaces)) {
      // Remove namespaces which are already present in nsListToRender
      for (const ancestorNamespace of ancestorNamespaces) {
        let alreadyListed = false;
        for (const nsToRender of nsListToRender) {
          if (
            nsToRender.prefix === ancestorNamespace.prefix &&
            nsToRender.namespaceURI === ancestorNamespace.namespaceURI
          ) {
            alreadyListed = true;
          }
        }

        if (!alreadyListed) {
          nsListToRender.push(ancestorNamespace);
        }
      }
    }

    nsListToRender.sort(this.nsCompare);

    //render namespaces
    res.push(
      ...nsListToRender.map((attr) => {
        if (attr.prefix) {
          return ` xmlns:${attr.prefix}="${attr.namespaceURI}"`;
        }
        return ` xmlns="${attr.namespaceURI}"`;
      }),
    );

    return { rendered: res.join(""), newDefaultNs };
  }

  /**
   * @param node Node
   */
  processInner(node, prefixesInScope, defaultNs, defaultNsForPrefix, ancestorNamespaces) {
    if (isDomNode.isCommentNode(node)) {
      return this.renderComment(node);
    }
    if (node.data) {
      return utils.encodeSpecialCharactersInText(node.data);
    }

    if (isDomNode.isElementNode(node)) {
      let i;
      let pfxCopy;
      const ns = this.renderNs(
        node,
        prefixesInScope,
        defaultNs,
        defaultNsForPrefix,
        ancestorNamespaces,
      );
      const res = ["<", node.tagName, ns.rendered, this.renderAttrs(node), ">"];

      for (i = 0; i < node.childNodes.length; ++i) {
        pfxCopy = prefixesInScope.slice(0);
        res.push(
          this.processInner(node.childNodes[i], pfxCopy, ns.newDefaultNs, defaultNsForPrefix, []),
        );
      }

      res.push("</", node.tagName, ">");
      return res.join("");
    }

    throw new Error(`Unable to canonicalize node type: ${node.nodeType}`);
  }

  // Thanks to deoxxa/xml-c14n for comment renderer
  renderComment(node: Comment) {
    if (!this.includeComments) {
      return "";
    }

    const isOutsideDocument = node.ownerDocument === node.parentNode;
    let isBeforeDocument = false;
    let isAfterDocument = false;

    if (isOutsideDocument) {
      let nextNode: ChildNode | null = node;
      let previousNode: ChildNode | null = node;

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

    const afterDocument = isAfterDocument ? "\n" : "";
    const beforeDocument = isBeforeDocument ? "\n" : "";
    const encodedText = utils.encodeSpecialCharactersInText(node.data);

    return `${afterDocument}<!--${encodedText}-->${beforeDocument}`;
  }

  /**
   * Perform canonicalization of the given node
   *
   * @param node
   * @api public
   */
  process(node: Node, options: CanonicalizationOrTransformationAlgorithmProcessOptions): string {
    options = options || {};
    const defaultNs = options.defaultNs || "";
    const defaultNsForPrefix = options.defaultNsForPrefix || {};
    const ancestorNamespaces = options.ancestorNamespaces || [];

    const prefixesInScope: string[] = [];
    for (let i = 0; i < ancestorNamespaces.length; i++) {
      prefixesInScope.push(ancestorNamespaces[i].prefix);
    }

    const res = this.processInner(
      node,
      prefixesInScope,
      defaultNs,
      defaultNsForPrefix,
      ancestorNamespaces,
    );
    return res;
  }

  getAlgorithmName() {
    return "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
  }
}

/**
 * Add c14n#WithComments here (very simple subclass)
 */
export class C14nCanonicalizationWithComments extends C14nCanonicalization {
  constructor() {
    super();
    this.includeComments = true;
  }

  getAlgorithmName() {
    return "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
  }
}
