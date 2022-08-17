global.crypto = require('node:crypto').webcrypto;
var crypto = require('../index');
var xpath = require('xpath');
var xmldom = require('@xmldom/xmldom');
var fs = require('fs');

exports['test with a document '] = async function (test) {
  var xml = fs.readFileSync('./test/static/valid_saml.xml', 'utf-8');
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var signature = new xmldom.DOMParser().parseFromString(xpath.select("/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']", doc)[0].toString());
  var sig = new crypto.SignedXml();
  sig.keyInfoProvider = new crypto.InMemKeyInfo(fs.readFileSync("./test/static/feide_public.pem", 'utf-8'));
  sig.loadSignature(signature);
  var result = await sig.checkSignature(xml);
  test.equal(result, true);
  test.done();
};

