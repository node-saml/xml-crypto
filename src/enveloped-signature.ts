import * as xpath from "xpath";
import * as isDomNode from "@xmldom/is-dom-node";

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
    const expectedSignatureValue = xpath.select1(
      ".//*[local-name(.)='SignatureValue']/text()",
      signatureNode,
    );
    if (isDomNode.isTextNode(expectedSignatureValue)) {
      const expectedSignatureValueData = expectedSignatureValue.data;

      const signatures = xpath.select(
        ".//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
        node,
      );
      for (const nodeSignature of Array.isArray(signatures) ? signatures : []) {
        const signatureValue = xpath.select1(
          ".//*[local-name(.)='SignatureValue']/text()",
          nodeSignature,
        );
        if (isDomNode.isTextNode(signatureValue)) {
          const signatureValueData = signatureValue.data;
          if (expectedSignatureValueData === signatureValueData) {
            if (nodeSignature.parentNode) {
              nodeSignature.parentNode.removeChild(nodeSignature);
            }
          }
        }
      }
    }
    return node;
  }

  getAlgorithmName(): CanonicalizationOrTransformAlgorithmType {
    return "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
  }
}
