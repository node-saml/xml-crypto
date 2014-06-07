var select = require('xpath.js')
  , dom = require('xmldom-fork-fixed').DOMParser
  , SignedXml = require('../lib/signed-xml.js').SignedXml
  , FileKeyInfo = require('../lib/signed-xml.js').FileKeyInfo
  , xml_assert = require('./xml-assert.js')
  , fs = require('fs')
  
module.exports = {    

  "signer adds increasing id atributes to elements": function (test) {    
    verifyAddsId(test, "wssecurity", "equal")
    verifyAddsId(test, null, "different") 
    test.done();   
  },


  "signer does not duplicate existing id attributes": function (test) {
    verifyDoesNotDuplicateIdAttributes(test, null, "")
    verifyDoesNotDuplicateIdAttributes(test, "wssecurity", "wsu:")
    
    test.done();
  },


  "signer creates signature with correct structure": function(test) {
    
    function DummyKeyInfo() {
      this.getKeyInfo = function(key) {
        return "dummy key info"
      }
    }

    function DummyDigest() {
  
      this.getHash = function(xml) {    
        return "dummy digest"
      }

      this.getAlgorithmName = function() {
        return "dummy digest algorithm"
      }
    }

    function DummySignatureAlgorithm() {
  
      this.getSignature = function(xml, signingKey) {            
        return "dummy signature"
      }

      this.getAlgorithmName = function() {
        return "dummy algorithm"
      }

    }

    function DummyTransformation() {
      this.process = function(node) {
        return "< x/>"
      }

      this.getAlgorithmName = function() {
        return "dummy transformation"
      }
    }

    function DummyCanonicalization() {
      this.process = function(node) {
        return "< x/>"
      }

       this.getAlgorithmName = function() {
        return "dummy canonicalization"
      }
    } 

    var xml = "<root><x xmlns=\"ns\"></x><y attr=\"value\"></y><z><w></w></z></root>"
    var sig = new SignedXml()


    SignedXml.CanonicalizationAlgorithms["http://DummyTransformation"] = DummyTransformation
    SignedXml.CanonicalizationAlgorithms["http://DummyCanonicalization"] = DummyCanonicalization
    SignedXml.HashAlgorithms["http://dummyDigest"] = DummyDigest
    SignedXml.SignatureAlgorithms["http://dummySignatureAlgorithm"] = DummySignatureAlgorithm

    sig.signatureAlgorithm = "http://dummySignatureAlgorithm"
    sig.keyInfoProvider = new DummyKeyInfo()
    sig.canonicalizationAlgorithm = "http://DummyCanonicalization"

    sig.addReference("//*[local-name(.)='x']", ["http://DummyTransformation"], "http://dummyDigest")
    sig.addReference("//*[local-name(.)='y']", ["http://DummyTransformation"], "http://dummyDigest")
    sig.addReference("//*[local-name(.)='w']", ["http://DummyTransformation"], "http://dummyDigest")

    sig.computeSignature(xml)
    var signature = sig.getSignatureXml()
    var expected = "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"+
                  "<SignedInfo>"+
                  "<CanonicalizationMethod Algorithm=\"dummy canonicalization\" />"+
                  "<SignatureMethod Algorithm=\"dummy algorithm\" />"+
                  "<Reference URI=\"#_0\">"+
                  "<Transforms>"+
                  "<Transform Algorithm=\"dummy transformation\" />"+
                  "</Transforms>"+
                  "<DigestMethod Algorithm=\"dummy digest algorithm\" />"+
                  "<DigestValue>dummy digest</DigestValue>"+
                  "</Reference>"+
                  "<Reference URI=\"#_1\">"+
                  "<Transforms>"+
                  "<Transform Algorithm=\"dummy transformation\" />"+
                  "</Transforms>"+
                  "<DigestMethod Algorithm=\"dummy digest algorithm\" />"+
                  "<DigestValue>dummy digest</DigestValue>"+
                  "</Reference>"+
                  "<Reference URI=\"#_2\">"+
                  "<Transforms>"+
                  "<Transform Algorithm=\"dummy transformation\" />"+
                  "</Transforms>"+
                  "<DigestMethod Algorithm=\"dummy digest algorithm\" />"+
                  "<DigestValue>dummy digest</DigestValue>"+
                  "</Reference>"+
                  "</SignedInfo>"+
                  "<SignatureValue>dummy signature</SignatureValue>"+
                  "<KeyInfo>"+
                  "dummy key info"+
                  "</KeyInfo>"+
                  "</Signature>"

   
    test.equal(expected, signature, "wrong signature format")

    var signedXml = sig.getSignedXml()
    var expectedSignedXml = "<root><x xmlns=\"ns\" Id=\"_0\"/><y attr=\"value\" Id=\"_1\"/><z><w Id=\"_2\"/></z>" +
                  "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"+
                  "<SignedInfo>"+
                  "<CanonicalizationMethod Algorithm=\"dummy canonicalization\"/>"+
                  "<SignatureMethod Algorithm=\"dummy algorithm\"/>"+
                  "<Reference URI=\"#_0\">"+
                  "<Transforms>"+
                  "<Transform Algorithm=\"dummy transformation\"/>"+
                  "</Transforms>"+
                  "<DigestMethod Algorithm=\"dummy digest algorithm\"/>"+
                  "<DigestValue>dummy digest</DigestValue>"+
                  "</Reference>"+
                  "<Reference URI=\"#_1\">"+
                  "<Transforms>"+
                  "<Transform Algorithm=\"dummy transformation\"/>"+
                  "</Transforms>"+
                  "<DigestMethod Algorithm=\"dummy digest algorithm\"/>"+
                  "<DigestValue>dummy digest</DigestValue>"+
                  "</Reference>"+
                  "<Reference URI=\"#_2\">"+
                  "<Transforms>"+
                  "<Transform Algorithm=\"dummy transformation\"/>"+
                  "</Transforms>"+
                  "<DigestMethod Algorithm=\"dummy digest algorithm\"/>"+
                  "<DigestValue>dummy digest</DigestValue>"+
                  "</Reference>"+
                  "</SignedInfo>"+
                  "<SignatureValue>dummy signature</SignatureValue>"+
                  "<KeyInfo>"+
                  "dummy key info"+
                  "</KeyInfo>"+
                  "</Signature>" +
                  "</root>"

    test.equal(expectedSignedXml, signedXml, "wrong signedXml format")



    var originalXmlWithIds = sig.getOriginalXmlWithIds()
    var expectedOriginalXmlWithIds = "<root><x xmlns=\"ns\" Id=\"_0\"/><y attr=\"value\" Id=\"_1\"/><z><w Id=\"_2\"/></z></root>"
    test.equal(expectedOriginalXmlWithIds, originalXmlWithIds, "wrong OriginalXmlWithIds")

    test.done();
  },



  "signer creates correct signature values": function(test) {

    var xml = "<root><x xmlns=\"ns\" Id=\"_0\"></x><y attr=\"value\" Id=\"_1\"></y><z><w Id=\"_2\"></w></z></root>"
    var sig = new SignedXml()
    sig.signingKey = fs.readFileSync("./test/static/client.pem")
    sig.keyInfoProvider = null

    sig.addReference("//*[local-name(.)='x']")
    sig.addReference("//*[local-name(.)='y']")
    sig.addReference("//*[local-name(.)='w']")

    sig.computeSignature(xml)
    var signedXml = sig.getSignedXml()
    var expected =  "<root><x xmlns=\"ns\" Id=\"_0\"/><y attr=\"value\" Id=\"_1\"/><z><w Id=\"_2\"/></z>" +
                    "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" +
                    "<SignedInfo>" +
                    "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
                    "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>" +
                    "<Reference URI=\"#_0\">" +
                    "<Transforms>" +
                    "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms>" +
                    "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>" +
                    "<DigestValue>b5GCZ2xpP5T7tbLWBTkOl4CYupQ=</DigestValue>" +
                    "</Reference>" +
                    "<Reference URI=\"#_1\">" +
                    "<Transforms>" +
                    "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
                    "</Transforms>" +
                    "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>" +
                    "<DigestValue>4Pq/sBri+AyOtxtSFsPSOyylyzk=</DigestValue>" +
                    "</Reference>" +
                    "<Reference URI=\"#_2\">" +
                    "<Transforms>" +
                    "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
                    "</Transforms>" +
                    "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>" +
                    "<DigestValue>6I7SDu1iV2YOajTlf+iMLIBfLnE=</DigestValue>" +
                    "</Reference>" +
                    "</SignedInfo>" +
                    "<SignatureValue>NejzGB9MDUddKCt3GL2vJhEd5q6NBuhLdQc3W4bJI5q34hk7Hk6zBRoW3OliX+/f7Hpi9y0INYoqMSUfrsAVm3IuPzUETKlI6xiNZo07ULRj1DwxRo6cU66ar1EKUQLRuCZas795FjB8jvUI2lyhcax/00uMJ+Cjf4bwAQ+9gOQ=</SignatureValue>" +
                    "</Signature>" +
                    "</root>"
   
    test.equal(expected, signedXml, "wrong signature format")

    test.done();
  },
 

 
  "correctly loads signature": function(test) {
    var xml = fs.readFileSync("./test/static/valid_signature.xml").toString()
    var doc = new dom().parseFromString(xml)    
    var node = select(doc, "/*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0]
    var sig = new SignedXml() 
    sig.loadSignature(node.toString())



    test.equal("http://www.w3.org/2001/10/xml-exc-c14n#", 
      sig.canonicalizationAlgorithm, 
      "wrong canonicalization method")
    
    test.equal("http://www.w3.org/2000/09/xmldsig#rsa-sha1", 
      sig.signatureAlgorithm, 
      "wrong signature method")

    test.equal("PI2xGt3XrVcxYZ34Kw7nFdq75c7Mmo7J0q7yeDhBprHuJal/KV9KyKG+Zy3bmQIxNwkPh0KMP5r1YMTKlyifwbWK0JitRCSa0Fa6z6+TgJi193yiR5S1MQ+esoQT0RzyIOBl9/GuJmXx/1rXnqrTxmL7UxtqKuM29/eHwF0QDUI=", 
      sig.signatureValue, 
      "wrong signature value")

    test.equal(sig.keyInfo, "<KeyInfo><dummyKey>1234</dummyKey></KeyInfo>", "keyInfo caluse not correctly loaded")

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

    test.done()
  },  
 
  "verify valid signature": function(test) {
    passValidSignature(test, "./test/static/valid_signature.xml")   
    passValidSignature(test, "./test/static/valid_signature wsu.xml", "wssecurity")
    passValidSignature(test, "./test/static/valid_signature_with_reference_keyInfo.xml")   
    passValidSignature(test, "./test/static/valid_signature_utf8.xml")   
    test.done() 
  },


  "fail invalid signature": function(test) {
    failInvalidSignature(test, "./test/static/invalid_signature - signature value.xml")
    failInvalidSignature(test, "./test/static/invalid_signature - hash.xml")    
    failInvalidSignature(test, "./test/static/invalid_signature - non existing reference.xml")
    failInvalidSignature(test, "./test/static/invalid_signature - changed content.xml")
    failInvalidSignature(test, "./test/static/invalid_signature - wsu - invalid signature value.xml", "wssecurity")
    failInvalidSignature(test, "./test/static/invalid_signature - wsu - hash.xml", "wssecurity")
    failInvalidSignature(test, "./test/static/invalid_signature - wsu - non existing reference.xml", "wssecurity")
    failInvalidSignature(test, "./test/static/invalid_signature - wsu - changed content.xml", "wssecurity")

    test.done()
  },
 

  "allow empty reference uri when signing": function(test) {
    var xml = "<root><x /></root>"
    var sig = new SignedXml()
    sig.signingKey = fs.readFileSync("./test/static/client.pem")
    sig.keyInfoProvider = null

    sig.addReference("//*[local-name(.)='root']", ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"], "http://www.w3.org/2000/09/xmldsig#sha1", "", "", "", true)  

    sig.computeSignature(xml)
    var signedXml = sig.getSignedXml()    
    var doc = new dom().parseFromString(signedXml)    
    var URI = select(doc, "//*[local-name(.)='Reference']/@URI")[0]            
    test.equal(URI.value, "", "uri should be empty but instead was " + URI.value)
    test.done()
  }

}

function passValidSignature(test, file, mode) {
  var xml = fs.readFileSync(file).toString()
  var res = verifySignature(xml, mode)
  test.equal(true, res, "expected signature to be valid, but it was reported invalid")
}


function failInvalidSignature(test, file, mode) {
  var xml = fs.readFileSync(file).toString()
  var res = verifySignature(xml, mode)
  test.equal(false, res, "expected signature to be invalid, but it was reported valid")  
}

function verifySignature(xml, mode) {
   
  var doc = new dom().parseFromString(xml)    
  var node = select(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0]
  
  var sig = new SignedXml(mode) 
  sig.keyInfoProvider = new FileKeyInfo("./test/static/client_public.pem")
  sig.loadSignature(node.toString())
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
  var attrs = select(doc, "//@*")
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

function nodeExists(test, doc, xpath) {  
  if (!doc && !xpath) return
  var node = select(doc, xpath)
  test.ok(node.length==1, "xpath " + xpath + " not found")
}
