const crypto = require("../index");
const xpath = require("xpath");
const xmldom = require("@xmldom/xmldom");
const fs = require("fs");
const expect = require("chai").expect;

let sigAlgs;

describe("HMAC tests", function () {
  beforeEach(function () {
    sigAlgs = crypto.SignedXml.SignatureAlgorithms;
    crypto.SignedXml.enableHMAC();
  });

  afterEach(function () {
    crypto.SignedXml.SignatureAlgorithms = sigAlgs;
  });

  it("test validating HMAC signature", function () {
    const xml = fs.readFileSync("./test/static/hmac_signature.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )[0];
    const sig = new crypto.SignedXml();
    sig.keyInfoProvider = new crypto.FileKeyInfo("./test/static/hmac.key");
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
  });

  it("test HMAC signature with incorrect key", function () {
    const xml = fs.readFileSync("./test/static/hmac_signature.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )[0];
    const sig = new crypto.SignedXml();
    sig.keyInfoProvider = new crypto.FileKeyInfo("./test/static/hmac-foobar.key");
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);

    expect(result).to.be.false;
  });

  it("test create and validate HMAC signature", function () {
    const xml = "<library>" + "<book>" + "<name>Harry Potter</name>" + "</book>" + "</library>";
    const sig = new crypto.SignedXml();
    sig.signingKey = fs.readFileSync("./test/static/hmac.key");
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
    sig.addReference("//*[local-name(.)='book']");
    sig.computeSignature(xml);

    const doc = new xmldom.DOMParser().parseFromString(sig.getSignedXml());
    const signature = xpath.select(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )[0];
    const verify = new crypto.SignedXml();
    verify.keyInfoProvider = new crypto.FileKeyInfo("./test/static/hmac.key");
    verify.loadSignature(signature);
    const result = verify.checkSignature(sig.getSignedXml());

    expect(result).to.be.true;
  });
});
