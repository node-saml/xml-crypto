const crypto = require("../index");
const xpath = require("xpath");
const xmldom = require("@xmldom/xmldom");
const fs = require("fs");
const expect = require("chai").expect;

describe("WS-Fed Metadata tests", function () {
  it("test validating WS-Fed Metadata", function () {
    const xml = fs.readFileSync("./test/static/wsfederation_metadata.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )[0];
    const sig = new crypto.SignedXml();
    sig.signingCert = fs.readFileSync("./test/static/wsfederation_metadata.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
  });
});
