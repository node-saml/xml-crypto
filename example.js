var select = require('./lib/xpath.js').SelectNodes
  , dom = require('xmldom').DOMParser
  , SignedXml = require('./lib/signed-xml.js').SignedXml
  , FileKeyInfo = require('./lib/signed-xml.js').FileKeyInfo  
  , fs = require('fs')

function signXml(xml, xpath, key, dest)
{
  var sig = new SignedXml()
  sig.signingKey = fs.readFileSync(key)
  sig.addReference(xpath)    
  sig.computeSignature(xml)
  fs.writeFileSync(dest, sig.getSignedXml())
}

function validateXml(xml, key)
{
  var doc = new dom().parseFromString(xml)    
  var signature = select(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0]
  var sig = new SignedXml()
  sig.keyInfoProvider = new FileKeyInfo(key)
  sig.loadSignature(signature.toString())
  var res = sig.checkSignature(xml)
  if (!res) console.log(sig.validationErrors)
  return res;
}

var xml = "<library>" +
            "<book>" +
              "<name>Harry Potter</name>" +
            "</book>"
          "</library>"

//sign an xml document
signXml(xml, 
  "//*[local-name(.)='book']", 
  "./test/static/client.pem", 
  "c:\\temp\\result.xml")

console.log("xml signed succesfully")

var signedXml = fs.readFileSync("c:\\temp\\result.xml").toString()
console.log("validating signature...")

//validate an xml document
if (validateXml(signedXml, "./test/static/client_public.pem"))
  console.log("signature is valid")
else
  console.log("signature not valid")

  
  
  
  
 
  
