var xpath = require('xpath.js');

exports.EnvelopedSignature = EnvelopedSignature;

function EnvelopedSignature() {
}

EnvelopedSignature.prototype.process = function (node) {   
  var signature = xpath(node.ownerDocument, "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];  
  if (signature) signature.parentNode.removeChild(signature)
  //return node.toString();
  return node
};

EnvelopedSignature.prototype.getAlgorithmName = function () {
  return "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
};
