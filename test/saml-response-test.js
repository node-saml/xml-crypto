global.crypto = require('node:crypto').webcrypto;
var crypto = require('../index');
var xpath = require('xpath');
var xmldom = require('@xmldom/xmldom');
var fs = require('fs');

exports['test validating SAML response'] = async function (test) {
  var xml = fs.readFileSync('./test/static/valid_saml.xml', 'utf-8');
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var signature = xpath.select("/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']", doc)[0];
  var sig = new crypto.SignedXml();
  sig.keyInfoProvider = new crypto.InMemKeyInfo(fs.readFileSync("./test/static/feide_public.pem", 'utf-8'));
  sig.loadSignature(signature);
  var result = await sig.checkSignature(xml);
  test.equal(result, true);
  test.done();
};

exports['test validating wrapped assertion signature'] = async function (test) {
  var xml = fs.readFileSync('./test/static/valid_saml_signature_wrapping.xml', 'utf-8');
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var assertion = xpath.select("//*[local-name(.)='Assertion']", doc)[0];
  var signature = xpath.select("//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']", assertion)[0];
  var sig = new crypto.SignedXml();
  sig.keyInfoProvider = new crypto.InMemKeyInfo(fs.readFileSync("./test/static/feide_public.pem", 'utf-8'));
  sig.loadSignature(signature);

  let error;
  try {
    await sig.checkSignature(xml);
  } catch(e) {
    error = e;
  }

  test.equal(
    error.message,
    'Cannot validate a document which contains multiple elements with the ' +
    'same value for the ID / Id / Id attributes, in order to prevent ' +
    'signature wrapping attack.'
  );
  test.done();
};

// exports['test validating SAML response where a namespace is defined outside the signed element'] = async function (test) {
//   var xml = fs.readFileSync('./test/static/saml_external_ns.xml', 'utf-8');
//   var doc = new xmldom.DOMParser().parseFromString(xml);
//   var signature = xpath.select("//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']", doc)[0];
//   var sig = new crypto.SignedXml();
//   sig.keyInfoProvider = new crypto.InMemKeyInfo(fs.readFileSync("./test/static/saml_external_ns.pem", 'utf-8'));
//   sig.loadSignature(signature);
//   var result = await sig.checkSignature(xml);
//   test.equal(result, true);
//   test.done();
// };

exports['test reference id does not contain quotes'] = async function (test) {
  var xml = fs.readFileSync('./test/static/id_with_quotes.xml', 'utf-8');
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var assertion = xpath.select("//*[local-name(.)='Assertion']", doc)[0];
  var signature = xpath.select("//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']", assertion)[0];
  var sig = new crypto.SignedXml();
  sig.keyInfoProvider = new crypto.InMemKeyInfo(fs.readFileSync("./test/static/feide_public.pem", 'utf-8'));
  sig.loadSignature(signature);

  let error;
  try {
    await sig.checkSignature(xml);
  } catch(e) {
    error = e;
  }

  test.equal(
    error.message,
    'Cannot validate a uri with quotes inside it'
  );
  test.done();
};

exports['test validating SAML response WithComments'] = async function (test) {
  var xml = fs.readFileSync('./test/static/valid_saml_withcomments.xml', 'utf-8');
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var signature = xpath.select("/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']", doc)[0];
  var sig = new crypto.SignedXml();
  sig.keyInfoProvider = new crypto.InMemKeyInfo(fs.readFileSync("./test/static/feide_public.pem", 'utf-8'));
  sig.loadSignature(signature);
  var result = await sig.checkSignature(xml);
  // This doesn't matter, just want to make sure that we don't fail due to unknown algorithm
  test.equal(result, false);
  test.done();
};
