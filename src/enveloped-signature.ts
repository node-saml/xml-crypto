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
      const matches = (Array.isArray(signatures) ? signatures : []).filter((nodeSignature) => {
        const signatureValue = xpath.select1(
          ".//*[local-name(.)='SignatureValue']/text()",
          nodeSignature,
        );
        return (
          isDomNode.isTextNode(signatureValue) && signatureValue.data === expectedSignatureValueData
        );
      });
      // The signer removed exactly one element. Several matches means a copy of the signature
      // was inserted after signing; removing all of them would strip that unsigned content from
      // the digested data, so refuse rather than guess which one to remove.
      if (matches.length > 1) {
        throw new Error(
          "Cannot validate a document which contains multiple Signature elements with the " +
            "same SignatureValue within the enveloped-signature transform, in order to " +
            "prevent signature wrapping attack.",
        );
      }
      const match = matches[0];
      if (match?.parentNode) {
        match.parentNode.removeChild(match);
      }
    }
    return node;
  }

  getAlgorithmName(): TransformAlgorithmURI {
    return XMLDSIG_URIS.TRANSFORM_ALGORITHMS.ENVELOPED_SIGNATURE;
  }
}
