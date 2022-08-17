global.crypto = require('node:crypto').webcrypto;
var select = require('xpath').select
  , dom = require('@xmldom/xmldom').DOMParser
  , SignedXml = require('../lib/signed-xml.js').SignedXml
  , FileKeyInfo = require('../lib/signed-xml.js').FileKeyInfo
  , fs = require('fs')
  , crypto = require('crypto')

module.exports = {

  // "signer adds increasing id atributes to elements": function (test) {
  //   verifyAddsId(test, "wssecurity", "equal")
  //   verifyAddsId(test, null, "different")
  //   test.done();
  // },

  // "signer adds references with namespaces": function(test) {
  //   verifyReferenceNS(test);
  //   test.done();
  // },

  // "signer does not duplicate existing id attributes": function (test) {
  //   verifyDoesNotDuplicateIdAttributes(test, null, "")
  //   verifyDoesNotDuplicateIdAttributes(test, "wssecurity", "wsu:")

  //   test.done();
  // },

  // "signer adds custom attributes to the signature root node": function(test) {
  //   verifyAddsAttrs(test);
  //   test.done();
  // },

  // "signer appends signature to the root node by default": function(test) {
  //   var xml = "<root><name>xml-crypto</name><repository>github</repository></root>"
  //   var sig = new SignedXml()

  //   sig.signingKey = fs.readFileSync("./test/static/client.pem")
  //   sig.addReference("//*[local-name(.)='name']")
  //   sig.computeSignature(xml);

  //   var doc = new dom().parseFromString(sig.getSignedXml())

  //   test.strictEqual(doc.documentElement.lastChild.localName, "Signature", "the signature must be appended to the root node by default");
  //   test.done();
  // },

  // "signer appends signature to a reference node": function(test) {
  //   var xml = "<root><name>xml-crypto</name><repository>github</repository></root>"
  //   var sig = new SignedXml()

  //   sig.signingKey = fs.readFileSync("./test/static/client.pem")
  //   sig.addReference("//*[local-name(.)='repository']")

  //   sig.computeSignature(xml, {
  //     location: {
  //       reference: '/root/name',
  //       action: 'append'
  //     }
  //   });

  //   var doc = new dom().parseFromString(sig.getSignedXml())
  //   var referenceNode = select('/root/name', doc)[0]

  //   test.strictEqual(referenceNode.lastChild.localName, "Signature", "the signature should be appended to root/name");
  //   test.done();
  // },

  // "signer prepends signature to a reference node": function(test) {
  //   var xml = "<root><name>xml-crypto</name><repository>github</repository></root>"
  //   var sig = new SignedXml()

  //   sig.signingKey = fs.readFileSync("./test/static/client.pem")
  //   sig.addReference("//*[local-name(.)='repository']")

  //   sig.computeSignature(xml, {
  //     location: {
  //       reference: '/root/name',
  //       action: 'prepend'
  //     }
  //   });

  //   var doc = new dom().parseFromString(sig.getSignedXml())
  //   var referenceNode = select('/root/name', doc)[0]

  //   test.strictEqual(referenceNode.firstChild.localName, "Signature", "the signature should be prepended to root/name");
  //   test.done();
  // },

  // "signer inserts signature before a reference node": function(test) {
  //   var xml = "<root><name>xml-crypto</name><repository>github</repository></root>"
  //   var sig = new SignedXml()

  //   sig.signingKey = fs.readFileSync("./test/static/client.pem")
  //   sig.addReference("//*[local-name(.)='repository']")

  //   sig.computeSignature(xml, {
  //     location: {
  //       reference: '/root/name',
  //       action: 'before'
  //     }
  //   });

  //   var doc = new dom().parseFromString(sig.getSignedXml())
  //   var referenceNode = select('/root/name', doc)[0]

  //   test.strictEqual(referenceNode.previousSibling.localName, "Signature", "the signature should be inserted before to root/name");
  //   test.done();
  // },

  // "signer inserts signature after a reference node": function(test) {
  //   var xml = "<root><name>xml-crypto</name><repository>github</repository></root>"
  //   var sig = new SignedXml()

  //   sig.signingKey = fs.readFileSync("./test/static/client.pem")
  //   sig.addReference("//*[local-name(.)='repository']")

  //   sig.computeSignature(xml, {
  //     location: {
  //       reference: '/root/name',
  //       action: 'after'
  //     }
  //   });

  //   var doc = new dom().parseFromString(sig.getSignedXml())
  //   var referenceNode = select('/root/name', doc)[0]

  //   test.strictEqual(referenceNode.nextSibling.localName, "Signature", "the signature should be inserted after to root/name");
  //   test.done();
  // },

  // "signer creates signature with correct structure": function(test) {

  //   function DummyKeyInfo() {
  //     this.getKeyInfo = function(key) {
  //       return "dummy key info"
  //     }
  //   }

  //   function DummyDigest() {

  //     this.getHash = function(xml) {
  //       return "dummy digest"
  //     }

  //     this.getAlgorithmName = function() {
  //       return "dummy digest algorithm"
  //     }
  //   }

  //   function DummySignatureAlgorithm() {

  //     this.getSignature = function(xml, signingKey) {
  //       return "dummy signature"
  //     }

  //     this.getAlgorithmName = function() {
  //       return "dummy algorithm"
  //     }

  //   }

  //   function DummyTransformation() {
  //     this.process = function(node) {
  //       return "< x/>"
  //     }

  //     this.getAlgorithmName = function() {
  //       return "dummy transformation"
  //     }
  //   }

  //   function DummyCanonicalization() {
  //     this.process = function(node) {
  //       return "< x/>"
  //     }

  //      this.getAlgorithmName = function() {
  //       return "dummy canonicalization"
  //     }
  //   }

  //   var xml = "<root><x xmlns=\"ns\"></x><y attr=\"value\"></y><z><w></w></z></root>"
  //   var sig = new SignedXml()


  //   SignedXml.CanonicalizationAlgorithms["http://DummyTransformation"] = DummyTransformation
  //   SignedXml.CanonicalizationAlgorithms["http://DummyCanonicalization"] = DummyCanonicalization
  //   SignedXml.HashAlgorithms["http://dummyDigest"] = DummyDigest
  //   SignedXml.SignatureAlgorithms["http://dummySignatureAlgorithm"] = DummySignatureAlgorithm

  //   sig.signatureAlgorithm = "http://dummySignatureAlgorithm"
  //   sig.keyInfoProvider = new DummyKeyInfo()
  //   sig.canonicalizationAlgorithm = "http://DummyCanonicalization"

  //   sig.addReference("//*[local-name(.)='x']", ["http://DummyTransformation"], "http://dummyDigest")
  //   sig.addReference("//*[local-name(.)='y']", ["http://DummyTransformation"], "http://dummyDigest")
  //   sig.addReference("//*[local-name(.)='w']", ["http://DummyTransformation"], "http://dummyDigest")

  //   sig.computeSignature(xml)
  //   var signature = sig.getSignatureXml()
  //   var expected = "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"+
  //                 "<SignedInfo>"+
  //                 "<CanonicalizationMethod Algorithm=\"dummy canonicalization\"/>"+
  //                 "<SignatureMethod Algorithm=\"dummy algorithm\"/>"+
  //                 "<Reference URI=\"#_0\">"+
  //                 "<Transforms>"+
  //                 "<Transform Algorithm=\"dummy transformation\"/>"+
  //                 "</Transforms>"+
  //                 "<DigestMethod Algorithm=\"dummy digest algorithm\"/>"+
  //                 "<DigestValue>dummy digest</DigestValue>"+
  //                 "</Reference>"+
  //                 "<Reference URI=\"#_1\">"+
  //                 "<Transforms>"+
  //                 "<Transform Algorithm=\"dummy transformation\"/>"+
  //                 "</Transforms>"+
  //                 "<DigestMethod Algorithm=\"dummy digest algorithm\"/>"+
  //                 "<DigestValue>dummy digest</DigestValue>"+
  //                 "</Reference>"+
  //                 "<Reference URI=\"#_2\">"+
  //                 "<Transforms>"+
  //                 "<Transform Algorithm=\"dummy transformation\"/>"+
  //                 "</Transforms>"+
  //                 "<DigestMethod Algorithm=\"dummy digest algorithm\"/>"+
  //                 "<DigestValue>dummy digest</DigestValue>"+
  //                 "</Reference>"+
  //                 "</SignedInfo>"+
  //                 "<SignatureValue>dummy signature</SignatureValue>"+
  //                 "<KeyInfo>"+
  //                 "dummy key info"+
  //                 "</KeyInfo>"+
  //                 "</Signature>"


  //   test.equal(expected, signature, "wrong signature format")

  //   var signedXml = sig.getSignedXml()
  //   var expectedSignedXml = "<root><x xmlns=\"ns\" Id=\"_0\"/><y attr=\"value\" Id=\"_1\"/><z><w Id=\"_2\"/></z>" +
  //                 "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"+
  //                 "<SignedInfo>"+
  //                 "<CanonicalizationMethod Algorithm=\"dummy canonicalization\"/>"+
  //                 "<SignatureMethod Algorithm=\"dummy algorithm\"/>"+
  //                 "<Reference URI=\"#_0\">"+
  //                 "<Transforms>"+
  //                 "<Transform Algorithm=\"dummy transformation\"/>"+
  //                 "</Transforms>"+
  //                 "<DigestMethod Algorithm=\"dummy digest algorithm\"/>"+
  //                 "<DigestValue>dummy digest</DigestValue>"+
  //                 "</Reference>"+
  //                 "<Reference URI=\"#_1\">"+
  //                 "<Transforms>"+
  //                 "<Transform Algorithm=\"dummy transformation\"/>"+
  //                 "</Transforms>"+
  //                 "<DigestMethod Algorithm=\"dummy digest algorithm\"/>"+
  //                 "<DigestValue>dummy digest</DigestValue>"+
  //                 "</Reference>"+
  //                 "<Reference URI=\"#_2\">"+
  //                 "<Transforms>"+
  //                 "<Transform Algorithm=\"dummy transformation\"/>"+
  //                 "</Transforms>"+
  //                 "<DigestMethod Algorithm=\"dummy digest algorithm\"/>"+
  //                 "<DigestValue>dummy digest</DigestValue>"+
  //                 "</Reference>"+
  //                 "</SignedInfo>"+
  //                 "<SignatureValue>dummy signature</SignatureValue>"+
  //                 "<KeyInfo>"+
  //                 "dummy key info"+
  //                 "</KeyInfo>"+
  //                 "</Signature>" +
  //                 "</root>"

  //   test.equal(expectedSignedXml, signedXml, "wrong signedXml format")



  //   var originalXmlWithIds = sig.getOriginalXmlWithIds()
  //   var expectedOriginalXmlWithIds = "<root><x xmlns=\"ns\" Id=\"_0\"/><y attr=\"value\" Id=\"_1\"/><z><w Id=\"_2\"/></z></root>"
  //   test.equal(expectedOriginalXmlWithIds, originalXmlWithIds, "wrong OriginalXmlWithIds")

  //   test.done();
  // },

  // "signer creates signature with correct structure (with prefix)": function(test) {
  //   var prefix = 'ds';

  //   function DummyKeyInfo() {
  //     this.getKeyInfo = function(key) {
  //       return "<ds:dummy>dummy key info</ds:dummy>"
  //     }
  //   }

  //   function DummyDigest() {

  //     this.getHash = function(xml) {
  //       return "dummy digest"
  //     }

  //     this.getAlgorithmName = function() {
  //       return "dummy digest algorithm"
  //     }
  //   }

  //   function DummySignatureAlgorithm() {

  //     this.getSignature = function(xml, signingKey) {
  //       return "dummy signature"
  //     }

  //     this.getAlgorithmName = function() {
  //       return "dummy algorithm"
  //     }

  //   }

  //   function DummyTransformation() {
  //     this.process = function(node) {
  //       return "< x/>"
  //     }

  //     this.getAlgorithmName = function() {
  //       return "dummy transformation"
  //     }
  //   }

  //   function DummyCanonicalization() {
  //     this.process = function(node) {
  //       return "< x/>"
  //     }

  //      this.getAlgorithmName = function() {
  //       return "dummy canonicalization"
  //     }
  //   }

  //   var xml = "<root><x xmlns=\"ns\"></x><y attr=\"value\"></y><z><w></w></z></root>"
  //   var sig = new SignedXml()


  //   SignedXml.CanonicalizationAlgorithms["http://DummyTransformation"] = DummyTransformation
  //   SignedXml.CanonicalizationAlgorithms["http://DummyCanonicalization"] = DummyCanonicalization
  //   SignedXml.HashAlgorithms["http://dummyDigest"] = DummyDigest
  //   SignedXml.SignatureAlgorithms["http://dummySignatureAlgorithm"] = DummySignatureAlgorithm

  //   sig.signatureAlgorithm = "http://dummySignatureAlgorithm"
  //   sig.keyInfoProvider = new DummyKeyInfo()
  //   sig.canonicalizationAlgorithm = "http://DummyCanonicalization"

  //   sig.addReference("//*[local-name(.)='x']", ["http://DummyTransformation"], "http://dummyDigest")
  //   sig.addReference("//*[local-name(.)='y']", ["http://DummyTransformation"], "http://dummyDigest")
  //   sig.addReference("//*[local-name(.)='w']", ["http://DummyTransformation"], "http://dummyDigest")

  //   sig.computeSignature(xml, { prefix: prefix });
  //   var signature = sig.getSignatureXml()

  //   var expected = "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"+
  //                 "<ds:SignedInfo>"+
  //                 "<ds:CanonicalizationMethod Algorithm=\"dummy canonicalization\"/>"+
  //                 "<ds:SignatureMethod Algorithm=\"dummy algorithm\"/>"+
  //                 "<ds:Reference URI=\"#_0\">"+
  //                 "<ds:Transforms>"+
  //                 "<ds:Transform Algorithm=\"dummy transformation\"/>"+
  //                 "</ds:Transforms>"+
  //                 "<ds:DigestMethod Algorithm=\"dummy digest algorithm\"/>"+
  //                 "<ds:DigestValue>dummy digest</ds:DigestValue>"+
  //                 "</ds:Reference>"+
  //                 "<ds:Reference URI=\"#_1\">"+
  //                 "<ds:Transforms>"+
  //                 "<ds:Transform Algorithm=\"dummy transformation\"/>"+
  //                 "</ds:Transforms>"+
  //                 "<ds:DigestMethod Algorithm=\"dummy digest algorithm\"/>"+
  //                 "<ds:DigestValue>dummy digest</ds:DigestValue>"+
  //                 "</ds:Reference>"+
  //                 "<ds:Reference URI=\"#_2\">"+
  //                 "<ds:Transforms>"+
  //                 "<ds:Transform Algorithm=\"dummy transformation\"/>"+
  //                 "</ds:Transforms>"+
  //                 "<ds:DigestMethod Algorithm=\"dummy digest algorithm\"/>"+
  //                 "<ds:DigestValue>dummy digest</ds:DigestValue>"+
  //                 "</ds:Reference>"+
  //                 "</ds:SignedInfo>"+
  //                 "<ds:SignatureValue>dummy signature</ds:SignatureValue>"+
  //                 "<ds:KeyInfo>"+
  //                 "<ds:dummy>dummy key info</ds:dummy>"+
  //                 "</ds:KeyInfo>"+
  //                 "</ds:Signature>"

  //   test.equal(expected, signature, "wrong signature format")

  //   var signedXml = sig.getSignedXml()
  //   var expectedSignedXml = "<root><x xmlns=\"ns\" Id=\"_0\"/><y attr=\"value\" Id=\"_1\"/><z><w Id=\"_2\"/></z>" +
  //                 "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"+
  //                 "<ds:SignedInfo>"+
  //                 "<ds:CanonicalizationMethod Algorithm=\"dummy canonicalization\"/>"+
  //                 "<ds:SignatureMethod Algorithm=\"dummy algorithm\"/>"+
  //                 "<ds:Reference URI=\"#_0\">"+
  //                 "<ds:Transforms>"+
  //                 "<ds:Transform Algorithm=\"dummy transformation\"/>"+
  //                 "</ds:Transforms>"+
  //                 "<ds:DigestMethod Algorithm=\"dummy digest algorithm\"/>"+
  //                 "<ds:DigestValue>dummy digest</ds:DigestValue>"+
  //                 "</ds:Reference>"+
  //                 "<ds:Reference URI=\"#_1\">"+
  //                 "<ds:Transforms>"+
  //                 "<ds:Transform Algorithm=\"dummy transformation\"/>"+
  //                 "</ds:Transforms>"+
  //                 "<ds:DigestMethod Algorithm=\"dummy digest algorithm\"/>"+
  //                 "<ds:DigestValue>dummy digest</ds:DigestValue>"+
  //                 "</ds:Reference>"+
  //                 "<ds:Reference URI=\"#_2\">"+
  //                 "<ds:Transforms>"+
  //                 "<ds:Transform Algorithm=\"dummy transformation\"/>"+
  //                 "</ds:Transforms>"+
  //                 "<ds:DigestMethod Algorithm=\"dummy digest algorithm\"/>"+
  //                 "<ds:DigestValue>dummy digest</ds:DigestValue>"+
  //                 "</ds:Reference>"+
  //                 "</ds:SignedInfo>"+
  //                 "<ds:SignatureValue>dummy signature</ds:SignatureValue>"+
  //                 "<ds:KeyInfo>"+
  //                 "<ds:dummy>dummy key info</ds:dummy>"+
  //                 "</ds:KeyInfo>"+
  //                 "</ds:Signature>" +
  //                 "</root>"

  //   test.equal(expectedSignedXml, signedXml, "wrong signedXml format")



  //   var originalXmlWithIds = sig.getOriginalXmlWithIds()
  //   var expectedOriginalXmlWithIds = "<root><x xmlns=\"ns\" Id=\"_0\"/><y attr=\"value\" Id=\"_1\"/><z><w Id=\"_2\"/></z></root>"
  //   test.equal(expectedOriginalXmlWithIds, originalXmlWithIds, "wrong OriginalXmlWithIds")

  //   test.done();
  // },

  // "signer creates correct signature values": function(test) {

  //   var xml = "<root><x xmlns=\"ns\" Id=\"_0\"></x><y attr=\"value\" Id=\"_1\"></y><z><w Id=\"_2\"></w></z></root>"
  //   var sig = new SignedXml()
  //   sig.signingKey = fs.readFileSync("./test/static/client.pem")
  //   sig.keyInfoProvider = null

  //   sig.addReference("//*[local-name(.)='x']")
  //   sig.addReference("//*[local-name(.)='y']")
  //   sig.addReference("//*[local-name(.)='w']")

  //   sig.computeSignature(xml)
  //   var signedXml = sig.getSignedXml()
  //   var expected =  "<root><x xmlns=\"ns\" Id=\"_0\"/><y attr=\"value\" Id=\"_1\"/><z><w Id=\"_2\"/></z>" +
  //                   "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" +
  //                   "<SignedInfo>" +
  //                   "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
  //                   "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>" +
  //                   "<Reference URI=\"#_0\">" +
  //                   "<Transforms>" +
  //                   "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms>" +
  //                   "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>" +
  //                   "<DigestValue>b5GCZ2xpP5T7tbLWBTkOl4CYupQ=</DigestValue>" +
  //                   "</Reference>" +
  //                   "<Reference URI=\"#_1\">" +
  //                   "<Transforms>" +
  //                   "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
  //                   "</Transforms>" +
  //                   "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>" +
  //                   "<DigestValue>4Pq/sBri+AyOtxtSFsPSOyylyzk=</DigestValue>" +
  //                   "</Reference>" +
  //                   "<Reference URI=\"#_2\">" +
  //                   "<Transforms>" +
  //                   "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
  //                   "</Transforms>" +
  //                   "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>" +
  //                   "<DigestValue>6I7SDu1iV2YOajTlf+iMLIBfLnE=</DigestValue>" +
  //                   "</Reference>" +
  //                   "</SignedInfo>" +
  //                   "<SignatureValue>NejzGB9MDUddKCt3GL2vJhEd5q6NBuhLdQc3W4bJI5q34hk7Hk6zBRoW3OliX+/f7Hpi9y0INYoqMSUfrsAVm3IuPzUETKlI6xiNZo07ULRj1DwxRo6cU66ar1EKUQLRuCZas795FjB8jvUI2lyhcax/00uMJ+Cjf4bwAQ+9gOQ=</SignatureValue>" +
  //                   "</Signature>" +
  //                   "</root>"

  //   test.equal(expected, signedXml, "wrong signature format")

  //   test.done();
  // },

  // "signer creates correct signature values using async callback": function (test) {

  //   function DummySignatureAlgorithm() {
  //     this.getSignature = function (signedInfo, signingKey, callback) {
  //       var signer = crypto.createSign("RSA-SHA1")
  //       signer.update(signedInfo)
  //       var res = signer.sign(signingKey, 'base64')
  //       //Do some asynchronous things here
  //       callback(null, res)
  //     }
  //     this.getAlgorithmName = function () {
  //       return "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
  //     }
  //   }

  //   var xml = "<root><x xmlns=\"ns\" Id=\"_0\"></x><y attr=\"value\" Id=\"_1\"></y><z><w Id=\"_2\"></w></z></root>"
  //   SignedXml.SignatureAlgorithms["http://dummySignatureAlgorithmAsync"] = DummySignatureAlgorithm
  //   var sig = new SignedXml()
  //   sig.signatureAlgorithm = "http://dummySignatureAlgorithmAsync"
  //   sig.signingKey = fs.readFileSync("./test/static/client.pem")
  //   sig.keyInfoProvider = null

  //   sig.addReference("//*[local-name(.)='x']")
  //   sig.addReference("//*[local-name(.)='y']")
  //   sig.addReference("//*[local-name(.)='w']")

  //   sig.computeSignature(xml, function(err) {
  //     var signedXml = sig.getSignedXml()
  //     var expected = "<root><x xmlns=\"ns\" Id=\"_0\"/><y attr=\"value\" Id=\"_1\"/><z><w Id=\"_2\"/></z>" +
  //       "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" +
  //       "<SignedInfo>" +
  //       "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
  //       "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>" +
  //       "<Reference URI=\"#_0\">" +
  //       "<Transforms>" +
  //       "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms>" +
  //       "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>" +
  //       "<DigestValue>b5GCZ2xpP5T7tbLWBTkOl4CYupQ=</DigestValue>" +
  //       "</Reference>" +
  //       "<Reference URI=\"#_1\">" +
  //       "<Transforms>" +
  //       "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
  //       "</Transforms>" +
  //       "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>" +
  //       "<DigestValue>4Pq/sBri+AyOtxtSFsPSOyylyzk=</DigestValue>" +
  //       "</Reference>" +
  //       "<Reference URI=\"#_2\">" +
  //       "<Transforms>" +
  //       "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
  //       "</Transforms>" +
  //       "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>" +
  //       "<DigestValue>6I7SDu1iV2YOajTlf+iMLIBfLnE=</DigestValue>" +
  //       "</Reference>" +
  //       "</SignedInfo>" +
  //       "<SignatureValue>NejzGB9MDUddKCt3GL2vJhEd5q6NBuhLdQc3W4bJI5q34hk7Hk6zBRoW3OliX+/f7Hpi9y0INYoqMSUfrsAVm3IuPzUETKlI6xiNZo07ULRj1DwxRo6cU66ar1EKUQLRuCZas795FjB8jvUI2lyhcax/00uMJ+Cjf4bwAQ+9gOQ=</SignatureValue>" +
  //       "</Signature>" +
  //       "</root>"

  //     test.equal(expected, signedXml, "wrong signature format")
  //     test.done();
  //   })
  // },

  // "correctly loads signature": function(test) {
  //   passLoadSignature(test, "./test/static/valid_signature.xml")
  //   passLoadSignature(test, "./test/static/valid_signature.xml", true)
  //   passLoadSignature(test, "./test/static/valid_signature_with_root_level_sig_namespace.xml")
  //   test.done()
  // },

  // "verify valid signature": function(test) {
  //   passValidSignature(test, "./test/static/valid_signature.xml")
  //   passValidSignature(test, "./test/static/valid_signature_with_lowercase_id_attribute.xml")
  //   passValidSignature(test, "./test/static/valid_signature wsu.xml", "wssecurity")
  //   passValidSignature(test, "./test/static/valid_signature_with_reference_keyInfo.xml")
  //   passValidSignature(test, "./test/static/valid_signature_with_whitespace_in_digestvalue.xml")
  //   passValidSignature(test, "./test/static/valid_signature_utf8.xml")
  //   passValidSignature(test, "./test/static/valid_signature_with_unused_prefixes.xml")
  //   test.done()
  // },

  // "fail invalid signature": function(test) {
  //   failInvalidSignature(test, "./test/static/invalid_signature - signature value.xml")
  //   failInvalidSignature(test, "./test/static/invalid_signature - hash.xml")
  //   failInvalidSignature(test, "./test/static/invalid_signature - non existing reference.xml")
  //   failInvalidSignature(test, "./test/static/invalid_signature - changed content.xml")
  //   failInvalidSignature(test, "./test/static/invalid_signature - wsu - invalid signature value.xml", "wssecurity")
  //   failInvalidSignature(test, "./test/static/invalid_signature - wsu - hash.xml", "wssecurity")
  //   failInvalidSignature(test, "./test/static/invalid_signature - wsu - non existing reference.xml", "wssecurity")
  //   failInvalidSignature(test, "./test/static/invalid_signature - wsu - changed content.xml", "wssecurity")

  //   test.done()
  // },

  // "allow empty reference uri when signing": function(test) {
  //   var xml = "<root><x /></root>"
  //   var sig = new SignedXml()
  //   sig.signingKey = fs.readFileSync("./test/static/client.pem")
  //   sig.keyInfoProvider = null

  //   sig.addReference("//*[local-name(.)='root']", ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"], "http://www.w3.org/2000/09/xmldsig#sha1", "", "", "", true)

  //   sig.computeSignature(xml)
  //   var signedXml = sig.getSignedXml()
  //   var doc = new dom().parseFromString(signedXml)
  //   var URI = select("//*[local-name(.)='Reference']/@URI", doc)[0]
  //   test.equal(URI.value, "", "uri should be empty but instead was " + URI.value)
  //   test.done()
  // },

  // "signer appends signature to a non-existing reference node": function(test) {
  //   var xml = "<root><name>xml-crypto</name><repository>github</repository></root>";
  //   var sig = new SignedXml();

  //   sig.signingKey = fs.readFileSync("./test/static/client.pem");
  //   sig.addReference("//*[local-name(.)='repository']");

  //   try {
  //       sig.computeSignature(xml, {
  //         location: {
  //           reference: '/root/foobar',
  //           action: 'append'
  //         }
  //       });
  //       test.ok(false);
  //   }
  //   catch (err) {
  //       test.ok(!(err instanceof TypeError));
  //   }
  //   test.done();
  // },

  // "signer adds existing prefixes": function(test) {
  //   function AssertionKeyInfo(assertionId) {
  //     this.getKeyInfo = function(key, prefix) {
  //       return '<wsse:SecurityTokenReference wsse11:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1" wsu:Id="0" ' +
  //             'xmlns:wsse11="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"> ' +
  //             '<wsse:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID">'+assertionId+'</wsse:KeyIdentifier>'
  //         '</wsse:SecurityTokenReference>';
  //     };
  //   }

  //   var xml =
  //     '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"> ' +
  //       '<SOAP-ENV:Header> ' +
  //         '<wsse:Security ' +
  //           'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" ' +
  //           'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"> ' +
  //           '<Assertion></Assertion> '+
  //         '</wsse:Security> '+
  //       '</SOAP-ENV:Header> '+
  //     '</SOAP-ENV:Envelope>'

  //   var sig = new SignedXml();
  //   sig.keyInfoProvider = new AssertionKeyInfo(
  //     "_81d5fba5c807be9e9cf60c58566349b1"
  //   );
  //   sig.signingKey = fs.readFileSync("./test/static/client.pem");
  //   sig.computeSignature(xml, {
  //     prefix: "ds",
  //     location: {
  //       reference: "//Assertion",
  //       action: "after"
  //     },
  //     existingPrefixes: {
  //       wsse: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
  //       wsu: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
  //     }
  //   });
  //   result = sig.getSignedXml();
  //   test.equal((result.match(/xmlns:wsu=/g) || []).length, 1)
  //   test.equal((result.match(/xmlns:wsse=/g) || []).length, 1)
  //   test.done();
  // }

}

function passValidSignature(test, file, mode) {
  var xml = fs.readFileSync(file).toString()
  var res = verifySignature(xml, mode)
  test.equal(true, res, "expected signature to be valid, but it was reported invalid")
}

function passLoadSignature(test, file, toString) {
  var xml = fs.readFileSync(file).toString()
  var doc = new dom().parseFromString(xml)
  var node = select("/*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']", doc)[0]
  var sig = new SignedXml()
  sig.loadSignature(toString ? node.toString() : node)

  test.equal("http://www.w3.org/2001/10/xml-exc-c14n#",
    sig.canonicalizationAlgorithm,
    "wrong canonicalization method")

  test.equal("http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    sig.signatureAlgorithm,
    "wrong signature method")

  test.equal("PI2xGt3XrVcxYZ34Kw7nFdq75c7Mmo7J0q7yeDhBprHuJal/KV9KyKG+Zy3bmQIxNwkPh0KMP5r1YMTKlyifwbWK0JitRCSa0Fa6z6+TgJi193yiR5S1MQ+esoQT0RzyIOBl9/GuJmXx/1rXnqrTxmL7UxtqKuM29/eHwF0QDUI=",
    sig.signatureValue,
    "wrong signature value")

  var keyInfo = select("//*[local-name(.)='KeyInfo']/*[local-name(.)='dummyKey']", sig.keyInfo[0])[0];
  test.equal(keyInfo.firstChild.data, "1234", "keyInfo clause not correctly loaded")

  test.equal(3, sig.references.length)

  var digests = ["b5GCZ2xpP5T7tbLWBTkOl4CYupQ=", "K4dI497ZCxzweDIrbndUSmtoezY=", "sH1gxKve8wlU8LlFVa2l6w3HMJ0="]


  for (var i=0; i<sig.references.length; i++) {
    var ref = sig.references[i]
    var expectedUri = "#_"+i
    test.equal(expectedUri, ref.uri, "wrong uri for index " + i + ". expected: " + expectedUri + " actual: " + ref.uri)
    test.equal(1, ref.transforms.length)
    test.equal("http://www.w3.org/2001/10/xml-exc-c14n#", ref.transforms[0])
    test.equal(digests[i], ref.digestValue)
    test.equal("http://www.w3.org/2000/09/xmldsig#sha1", ref.digestAlgorithm)
  }
}

function failInvalidSignature(test, file, mode) {
  var xml = fs.readFileSync(file).toString()
  var res = verifySignature(xml, mode)
  test.equal(false, res, "expected signature to be invalid, but it was reported valid")
}

function verifySignature(xml, mode) {

  var doc = new dom().parseFromString(xml)
  var node = select("//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']", doc)[0]

  var sig = new SignedXml(mode)
  sig.keyInfoProvider = new FileKeyInfo("./test/static/client_public.pem")
  sig.loadSignature(node)
  var res = sig.checkSignature(xml)
  console.log(sig.validationErrors)
  return res;
}

function verifyDoesNotDuplicateIdAttributes(test, mode, prefix) {
  var xml = "<x xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' " + prefix + "Id='_1'></x>"
  var sig = new SignedXml(mode)
  sig.signingKey = fs.readFileSync("./test/static/client.pem")
  sig.addReference("//*[local-name(.)='x']")
  sig.computeSignature(xml)
  var signedxml = sig.getOriginalXmlWithIds()
  var doc = new dom().parseFromString(signedxml)
  var attrs = select("//@*", doc)
  test.equals(2, attrs.length, "wrong nuber of attributes")

}

function verifyAddsId(test, mode, nsMode) {
  var xml = "<x xmlns=\"ns\"></x><y attr=\"value\"></y><z><w></w></z>"
  var sig = new SignedXml(mode)
  sig.signingKey = fs.readFileSync("./test/static/client.pem")

  sig.addReference("//*[local-name(.)='x']")
  sig.addReference("//*[local-name(.)='y']")
  sig.addReference("//*[local-name(.)='w']")

  sig.computeSignature(xml)
  var signedxml = sig.getOriginalXmlWithIds()
  var doc = new dom().parseFromString(signedxml)

  op = nsMode == "equal" ? "=" : "!="

  var xpath = "//*[local-name(.)='{elem}' and '_{id}' = @*[local-name(.)='Id' and namespace-uri(.)" + op + "'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd']]"

  //verify each of the signed nodes now has an "Id" attribute with the right value
  nodeExists(test, doc, xpath.replace("{id}", "0").replace("{elem}", "x"))
  nodeExists(test, doc, xpath.replace("{id}", "1").replace("{elem}", "y"))
  nodeExists(test, doc, xpath.replace("{id}", "2").replace("{elem}", "w"))

}

function verifyAddsAttrs(test) {
  var xml = "<root xmlns=\"ns\"><name>xml-crypto</name><repository>github</repository></root>"
  var sig = new SignedXml()
  var attrs = {
    Id: 'signatureTest',
    data: 'dataValue',
    xmlns: 'http://custom-xmlns#'
  }

  sig.signingKey = fs.readFileSync("./test/static/client.pem")

  sig.addReference("//*[local-name(.)='name']")

  sig.computeSignature(xml, {
    attrs: attrs
  })

  var signedXml = sig.getSignatureXml()
  var doc = new dom().parseFromString(signedXml)
  var signatureNode = doc.documentElement

  test.strictEqual(signatureNode.getAttribute("Id"), attrs.Id, "Id attribute is not equal to the expected value: \"" + attrs.Id + "\"")
  test.strictEqual(signatureNode.getAttribute("data"), attrs.data, "data attribute is not equal to the expected value: \"" + attrs.data + "\"")
  test.notStrictEqual(signatureNode.getAttribute("xmlns"), attrs.xmlns, "xmlns attribute can not be overridden")
  test.strictEqual(signatureNode.getAttribute("xmlns"), "http://www.w3.org/2000/09/xmldsig#", "xmlns attribute is not equal to the expected value: \"http://www.w3.org/2000/09/xmldsig#\"")
}

function verifyReferenceNS(test) {
  var xml = "<root xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"><name wsu:Id=\"_1\">xml-crypto</name><repository wsu:Id=\"_2\">github</repository></root>"
  var sig = new SignedXml("wssecurity")

  sig.signingKey = fs.readFileSync("./test/static/client.pem")

  sig.addReference("//*[@wsu:Id]")

  sig.computeSignature(xml, {
    existingPrefixes: {
      wsu: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    }
  })

  var signedXml = sig.getSignatureXml()
  var doc = new dom().parseFromString(signedXml)
  var references = select("//*[local-name(.)='Reference']", doc)
  test.equal(references.length, 2)
}

function nodeExists(test, doc, xpath) {
  if (!doc && !xpath) return
  var node = select(xpath, doc)
  test.ok(node.length==1, "xpath " + xpath + " not found")
}
