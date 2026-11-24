import { isDescendantOf, isSignatureElement } from "./utils";

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
      const signature = Array.from(node.childNodes ?? []).find(isSignatureElement);
      if (signature?.parentNode) {
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
