import * as xpath from "xpath";
import * as isDomNode from "@xmldom/is-dom-node";
import { XMLDSIG_URIS } from "./xmldsig-uris";
import * as utils from "./utils";
import type { TransformAlgorithmOptions, TransformAlgorithmURI, TransformAlgorithm } from "./types";

export class EnvelopedSignature implements TransformAlgorithm {
  protected includeComments = false;

  constructor() {
    this.includeComments = false;
  }

  process(node: Node, options: TransformAlgorithmOptions): Node {
    if (null == options.signatureNode) {
      const signature = xpath.select1(
        `.//*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_URIS.NAMESPACES.ds}']`,
        node,
      );
      if (isDomNode.isNodeLike(signature) && signature.parentNode) {
        signature.parentNode.removeChild(signature);
      }
      return node;
    }
    const signatureNode = options.signatureNode;
    // Signing: `signatureNode` is the signature under construction, already resolved into this
    // subtree. It has no SignatureValue yet, so remove exactly that element.
    if (utils.isDescendantOf(signatureNode, node) && signatureNode.parentNode) {
      signatureNode.parentNode.removeChild(signatureNode);
      return node;
    }
    // Verifying: `signatureNode` was loaded from a separate parse, so find the matching
    // signature in this subtree by its SignatureValue.
    const expectedSignatureValue = xpath.select1(
      ".//*[local-name(.)='SignatureValue']/text()",
      signatureNode,
    );
    if (isDomNode.isTextNode(expectedSignatureValue)) {
      const expectedSignatureValueData = expectedSignatureValue.data;

      const signatures = xpath.select(
        `.//*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_URIS.NAMESPACES.ds}']`,
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

  getAlgorithmName(): TransformAlgorithmURI {
    return XMLDSIG_URIS.TRANSFORM_ALGORITHMS.ENVELOPED_SIGNATURE;
  }
}
