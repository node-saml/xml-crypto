const select = require("xpath").select;
const xmldom = require("@xmldom/xmldom");
const SignedXml = require("../lib/signed-xml.js").SignedXml;
const fs = require("fs");
const xpath = require("xpath");
const crypto = require("../index.js");
const expect = require("chai").expect;

describe("KeyInfo tests", function () {
  it("adds X509Certificate element during signature", function () {
    const xml = "<root><x /></root>";
    const sig = new SignedXml();
    sig.privateKey = fs.readFileSync("./test/static/client.pem");
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");
    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();
    const doc = new xmldom.DOMParser().parseFromString(signedXml);
    const x509 = select("//*[local-name(.)='X509Certificate']", doc.documentElement);
    expect(x509.length, "X509Certificate element should exist").to.equal(1);
  });

  it("make sure private hmac key is not leaked due to key confusion", function () {
    const xml = "<library>" + "<book>" + "<name>Harry Potter</name>" + "</book>" + "</library>";
    const sig = new crypto.SignedXml();
    sig.privateKey = fs.readFileSync("./test/static/hmac.key");
    sig.publicCert = fs.readFileSync("./test/static/hmac.key");
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
    sig.enableHMAC();
    sig.addReference("//*[local-name(.)='book']");
    sig.computeSignature(xml);

    const doc = new xmldom.DOMParser().parseFromString(sig.getSignedXml());

    const keyInfo = xpath.select("//*[local-name(.)='KeyInfo']", doc)[0];

    expect(keyInfo).to.be.undefined;
  });
});