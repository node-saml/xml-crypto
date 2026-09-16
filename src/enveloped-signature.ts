import * as xpath from "xpath";
import * as isDomNode from "@xmldom/is-dom-node";
import { isDescendantOf } from "./utils";

import type {
  CanonicalizationOrTransformationAlgorithm,
  CanonicalizationOrTransformationAlgorithmProcessOptions,
  CanonicalizationOrTransformAlgorithmType,
} from "./types";

export class EnvelopedSignature implements CanonicalizationOrTransformationAlgorithm {
  protected includeComments = false;

  constructor() {
    this.includeComments = false;
  }

  process(node: Node, options: CanonicalizationOrTransformationAlgorithmProcessOptions): Node {
    if (null == options.signatureNode) {
      const signature = xpath.select1(
        "./*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
        node,
      );
      if (isDomNode.isNodeLike(signature) && signature.parentNode) {
        signature.parentNode.removeChild(signature);
      }
      return node;
    }
    const signatureNode = options.signatureNode;
    if (isDescendantOf(signatureNode, node) && signatureNode.parentNode) {
      signatureNode.parentNode.removeChild(signatureNode);
    }
    return node;
  }

  getAlgorithmName(): CanonicalizationOrTransformAlgorithmType {
    return "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
  }
}
