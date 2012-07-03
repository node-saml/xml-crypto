var xpath = require('./xpath');

exports.EnvelopedSignature = EnvelopedSignature;

function EnvelopedSignature() {
}

EnvelopedSignature.prototype.process = function (node) {
  var signature = xpath.SelectNodes(node.ownerDocument, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];

  var xml = "" + node;
  var sigXml = "" + signature;
  
  var cleaned = xml.replace(sigXml, '');
  return cleaned;
};

EnvelopedSignature.prototype.getAlgorithmName = function () {
  return "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
};
