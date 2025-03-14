var crypto = require("../index");
var xpath = require("xpath");
var xmldom = require("@xmldom/xmldom");
var fs = require("fs");

exports["test validating SAML response"] = function (test) {
  var xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var signature = xpath.select(
    "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    doc
  )[0];
  var sig = new crypto.SignedXml();
  sig.keyInfoProvider = new crypto.FileKeyInfo("./test/static/feide_public.pem");
  sig.loadSignature(signature);
  var result = sig.checkSignature(xml);
  test.equal(result, true);
  test.done();
};

exports["test validating wrapped assertion signature"] = function (test) {
  var xml = fs.readFileSync("./test/static/valid_saml_signature_wrapping.xml", "utf-8");
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var assertion = xpath.select("//*[local-name(.)='Assertion']", doc)[0];
  var signature = xpath.select(
    "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    assertion
  )[0];
  var sig = new crypto.SignedXml();
  sig.keyInfoProvider = new crypto.FileKeyInfo("./test/static/feide_public.pem");
  sig.loadSignature(signature);
  test.throws(
    function () {
      sig.checkSignature(xml);
    },
    Error,
    "Should not validate a document which contains multiple elements with the " +
      "same value for the ID / Id / Id attributes, in order to prevent " +
      "signature wrapping attack."
  );
  test.done();
};

exports["test validating SAML response where a namespace is defined outside the signed element"] =
  function (test) {
    var xml = fs.readFileSync("./test/static/saml_external_ns.xml", "utf-8");
    var doc = new xmldom.DOMParser().parseFromString(xml);
    var signature = xpath.select(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )[0];
    var sig = new crypto.SignedXml();
    sig.keyInfoProvider = new crypto.FileKeyInfo("./test/static/saml_external_ns.pem");
    sig.loadSignature(signature);
    var result = sig.checkSignature(xml);
    test.equal(result, true);
    test.done();
  };

exports["test reference id does not contain quotes"] = function (test) {
  var xml = fs.readFileSync("./test/static/id_with_quotes.xml", "utf-8");
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var assertion = xpath.select("//*[local-name(.)='Assertion']", doc)[0];
  var signature = xpath.select(
    "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    assertion
  )[0];
  var sig = new crypto.SignedXml();
  sig.keyInfoProvider = new crypto.FileKeyInfo("./test/static/feide_public.pem");
  sig.loadSignature(signature);
  test.throws(
    function () {
      sig.checkSignature(xml);
    },
    Error,
    "id should not contain quotes"
  );
  test.done();
};

exports["test validating SAML response WithComments"] = function (test) {
  var xml = fs.readFileSync("./test/static/valid_saml_withcomments.xml", "utf-8");
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var signature = xpath.select(
    "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    doc
  )[0];
  var sig = new crypto.SignedXml();
  sig.keyInfoProvider = new crypto.FileKeyInfo("./test/static/feide_public.pem");
  sig.loadSignature(signature);
  var result = sig.checkSignature(xml);
  // This doesn't matter, just want to make sure that we don't fail due to unknown algorithm
  test.equal(result, false);
  test.done();
};

exports["test validating SAML response with digest comment"] = function (test) {
  var xml = fs.readFileSync("./test/static/valid_saml_with_digest_comment.xml", "utf-8");
  var doc = new xmldom.DOMParser().parseFromString(xml);
  const assertion = xpath.select1("//*[local-name(.)='Assertion']", doc);
  const signature = xpath.select1(
    "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    assertion,
  );
  var sig = new crypto.SignedXml();
  sig.keyInfoProvider = new crypto.FileKeyInfo("./test/static/feide_public.pem");
  sig.loadSignature(signature);
  var result = sig.checkSignature(xml);
  test.equal(sig.references[0].digestValue, "RnNjoyUguwze5w2R+cboyTHlkQk=");
  test.equal(result, false);
  test.done();
};

exports["test signature contains a `SignedInfo` node"] = function (test) {
  var xml = fs.readFileSync("./test/static/invalid_saml_no_signed_info.xml", "utf-8");
  var doc = new xmldom.DOMParser().parseFromString(xml);
  const node = xpath.select1(
    "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    doc,
  );
  var sig = new crypto.SignedXml();
  sig.keyInfoProvider = new crypto.FileKeyInfo("./test/static/feide_public.pem");
  test.throws(
    function () {
      sig.loadSignature(node);
    },
    Error,
    "no signed info node found"
  );
  test.done();
};

exports["test validation ignores an additional wrapped `SignedInfo` node"] = function (test) {
  var xml = fs.readFileSync("./test/static/saml_wrapped_signed_info_node.xml", "utf-8");
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var assertion = xpath.select("//*[local-name(.)='Assertion']", doc)[0];
  var signature = xpath.select(
    "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    assertion
  )[0];
  var sig = new crypto.SignedXml();
  sig.keyInfoProvider = new crypto.FileKeyInfo("./test/static/saml_external_ns.pem");
  sig.loadSignature(signature);
  test.equal(sig.references.length, 1);
  var result = sig.checkSignature(xml);
  test.equal(result, true);
  test.done();
};

exports["test signature does not contain multiple `SignedInfo` nodes"] = function (test) {
  var xml = fs.readFileSync("./test/static/saml_multiple_signed_info_nodes.xml", "utf-8");
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var assertion = xpath.select("//*[local-name(.)='Assertion']", doc)[0];
  var signature = xpath.select(
    "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    assertion
  )[0];
  var sig = new crypto.SignedXml();
  sig.keyInfoProvider = new crypto.FileKeyInfo("./test/static/saml_external_ns.pem");
  test.throws(
    function () {
      sig.loadSignature(signature);
    },
    Error,
    "could not load signature that contains multiple SignedInfo nodes"
  );
  test.done();
};
