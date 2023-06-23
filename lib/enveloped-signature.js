const xpath = require("xpath");
const utils = require("./utils");

/**
 * @type { import("../index.d.ts").CanonicalizationOrTransformationAlgorithm}
 */
class EnvelopedSignature {
  process(node, options) {
    if (null == options.signatureNode) {
      const signature = xpath.select(
        "./*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
        node
      )[0];
      if (signature) {
        signature.parentNode.removeChild(signature);
      }
      return node;
    }
    const signatureNode = options.signatureNode;
    const expectedSignatureValue = utils.findFirst(
      signatureNode,
      ".//*[local-name(.)='SignatureValue']/text()"
    ).data;
    const signatures = xpath.select(
      ".//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      node
    );
    for (const h in signatures) {
      if (!signatures.hasOwnProperty(h)) {
        continue;
      }
      const nodeSignature = signatures[h];
      const signatureValue = utils.findFirst(
        nodeSignature,
        ".//*[local-name(.)='SignatureValue']/text()"
      ).data;
      if (expectedSignatureValue === signatureValue) {
        nodeSignature.parentNode.removeChild(nodeSignature);
      }
    }
    return node;
  }

  getAlgorithmName() {
    return "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
  }
}

module.exports = {
  EnvelopedSignature,
};
