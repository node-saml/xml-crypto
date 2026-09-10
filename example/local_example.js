/* eslint-disable no-console */
// Run with `npm run example`, requires one-time `npm run build` to generate `/lib` code (and re-run if you update `/src`)

const select = require("xpath").select
const dom = require("@xmldom/xmldom").DOMParser;
const SignedXml = require("../").SignedXml;
const fs = require("fs");

function signXml(xml, xpath, key, dest, cert) {
  const sig = new SignedXml();
  sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#"
  sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
  sig.privateKey = fs.readFileSync(__dirname + "/" + key);
  sig.publicCert = fs.readFileSync(__dirname + "/" + cert); // To populate KeyInfo, as an example
  sig.addReference({
    xpath,
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
  });
  sig.computeSignature(xml);
  fs.writeFileSync(__dirname + "/" + dest, sig.getSignedXml());
}

function validateXml(xml, key) {
  const doc = new dom().parseFromString(xml);
  const signature = select(
    "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    doc,
  )[0];
  const sig = new SignedXml();
  sig.publicCert = fs.readFileSync(__dirname + "/" + key); // Note since the XML has a KeyInfo, this cert is NOT doing anything!
  // Validate the cert in `KeyInfo` on your own if that is your security model. See: <https://github.com/node-saml/xml-crypto/discussions/399>
  sig.loadSignature(signature.toString());
  const res = sig.checkSignature(xml);
  if (!res) {
    console.log(sig.validationErrors);
  }
  return res;
}

const xml = "<library>" + "<book>" + "<name>Harry Potter</name>" + "</book>" + "</library>";

//sign an xml document
signXml(xml, "//*[local-name(.)='book']", "client.pem", "result.xml", "client_public.pem");

console.log("xml signed successfully");

const signedXml = fs.readFileSync(__dirname + "/" + "result.xml").toString();
console.log("validating signature...");

//validate an xml document
if (validateXml(signedXml, "client_public.pem")) {
  console.log("signature is valid");
} else {
  console.log("signature not valid");
}