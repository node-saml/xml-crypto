var xpath = require("xpath");
var utils = require("./utils");

exports.EnvelopedSignature = EnvelopedSignature;

function EnvelopedSignature() {}

EnvelopedSignature.prototype.process = function (node, options) {
  if (null == options.signatureNode) {
    // leave this for the moment...
    var signature = xpath.select(
      "./*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      node
    )[0];
    if (signature) signature.parentNode.removeChild(signature);
    return node;
  }
  var signatureNode = options.signatureNode;
  var expectedSignatureValue = utils.findFirst(
    signatureNode,
    ".//*[local-name(.)='SignatureValue']/text()"
  ).data;
  var signatures = xpath.select(
    ".//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    node
  );
  for (var h in signatures) {
    if (!signatures.hasOwnProperty(h)) continue;
    var nodeSignature = signatures[h];
    var signatureValue = utils.findFirst(
      nodeSignature,
      ".//*[local-name(.)='SignatureValue']/text()"
    ).data;
    if (expectedSignatureValue === signatureValue) {
      nodeSignature.parentNode.removeChild(nodeSignature);
    }
  }
  return node;
};

EnvelopedSignature.prototype.getAlgorithmName = function () {
  return "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
};
