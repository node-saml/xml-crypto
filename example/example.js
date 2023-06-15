/* eslint-disable no-console */

var select = require("xml-crypto").xpath;
var dom = require("@xmldom/xmldom").DOMParser;
var SignedXml = require("xml-crypto").SignedXml;
var FileKeyInfo = require("xml-crypto").FileKeyInfo;
var fs = require("fs");

function signXml(xml, xpath, key, dest) {
  var sig = new SignedXml();
  sig.signingKey = fs.readFileSync(key);
  sig.addReference(xpath);
  sig.computeSignature(xml);
  fs.writeFileSync(dest, sig.getSignedXml());
}

function validateXml(xml, key) {
  var doc = new dom().parseFromString(xml);
  var signature = select(
    "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    doc
  )[0];
  var sig = new SignedXml();
  sig.keyInfoProvider = new FileKeyInfo(key);
  sig.loadSignature(signature.toString());
  var res = sig.checkSignature(xml);
  if (!res) {
    console.log(sig.validationErrors);
  }
  return res;
}

var xml = "<library>" + "<book>" + "<name>Harry Potter</name>" + "</book>" + "</library>";

//sign an xml document
signXml(xml, "//*[local-name(.)='book']", "client.pem", "result.xml");

console.log("xml signed successfully");

var signedXml = fs.readFileSync("result.xml").toString();
console.log("validating signature...");

//validate an xml document
if (validateXml(signedXml, "client_public.pem")) {
  console.log("signature is valid");
} else {
  console.log("signature not valid");
}
