var crypto = require("../index");
var xpath = require("xpath");
var xmldom = require("@xmldom/xmldom");
var fs = require("fs");
const { sign } = require("crypto");
var expect = require("chai").expect;

describe("HMAC tests", function () {
  it("test validating HMAC signature", function () {
    var xml = fs.readFileSync("./test/static/hmac_signature.xml", "utf-8");
    var doc = new xmldom.DOMParser().parseFromString(xml);
    var signature = xpath.select(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )[0];
    var sig = new crypto.SignedXml();
    sig.enableHMAC();
    sig.signingCert = fs.readFileSync("./test/static/hmac.key");
    sig.loadSignature(signature);
    var result = sig.checkSignature(xml);

    expect(result).to.be.true;
  });

  it("test HMAC signature with incorrect key", function () {
    var xml = fs.readFileSync("./test/static/hmac_signature.xml", "utf-8");
    var doc = new xmldom.DOMParser().parseFromString(xml);
    var signature = xpath.select(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )[0];
    var sig = new crypto.SignedXml();
    sig.enableHMAC();
    sig.signingCert = fs.readFileSync("./test/static/hmac-foobar.key");
    sig.loadSignature(signature);
    var result = sig.checkSignature(xml);

    expect(result).to.be.false;
  });

  it("test create and validate HMAC signature", function () {
    var xml = "<library>" + "<book>" + "<name>Harry Potter</name>" + "</book>" + "</library>";
    var sig = new crypto.SignedXml();
    sig.enableHMAC();
    sig.signingKey = fs.readFileSync("./test/static/hmac.key");
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
    sig.addReference("//*[local-name(.)='book']");
    sig.computeSignature(xml);

    var doc = new xmldom.DOMParser().parseFromString(sig.getSignedXml());
    var signature = xpath.select(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )[0];
    var verify = new crypto.SignedXml();
    verify.enableHMAC();
    verify.signingCert = fs.readFileSync("./test/static/hmac.key");
    verify.loadSignature(signature);
    var result = verify.checkSignature(sig.getSignedXml());

    expect(result).to.be.true;
  });
});
