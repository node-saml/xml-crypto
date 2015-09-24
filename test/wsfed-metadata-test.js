var crypto = require('../index');
var xmldom = require('xmldom');
var fs = require('fs');

exports['test validating WS-Fed Metadata'] = function (test) {
  var xml = fs.readFileSync('./test/static/wsfederation_metadata.xml', 'utf-8');
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var signature = crypto.xpath(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
  var sig = new crypto.SignedXml();
  sig.keyInfoProvider = new crypto.FileKeyInfo("./test/static/wsfederation_metadata.pem");
  sig.loadSignature(signature);
  var result = sig.checkSignature(xml);
  test.equal(result, true);
  test.done();
};
