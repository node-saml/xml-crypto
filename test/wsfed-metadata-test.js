var crypto = require("../index");
var xpath = require("xpath");
var xmldom = require("@xmldom/xmldom");
var fs = require("fs");
var expect = require("chai").expect;

describe("WS-Fed Metadata tests", function () {
  it("test validating WS-Fed Metadata", function () {
    var xml = fs.readFileSync("./test/static/wsfederation_metadata.xml", "utf-8");
    var doc = new xmldom.DOMParser().parseFromString(xml);
    var signature = xpath.select(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )[0];
    var sig = new crypto.SignedXml();
    sig.signingCert = fs.readFileSync("./test/static/wsfederation_metadata.pem");
    sig.loadSignature(signature);
    var result = sig.checkSignature(xml);

    expect(result).to.be.true;
  });
});
