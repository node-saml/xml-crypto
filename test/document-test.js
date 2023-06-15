const crypto = require("../index");
const xpath = require("xpath");
const xmldom = require("@xmldom/xmldom");
const fs = require("fs");
const expect = require("chai").expect;

describe("Document tests", function () {
  it("test with a document (using FileKeyInfo)", function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = new xmldom.DOMParser().parseFromString(
      xpath
        .select(
          "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
          doc
        )[0]
        .toString()
    );
    const sig = new crypto.SignedXml();
    sig.signingCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
  });

  it("test with a document (using StringKeyInfo)", function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = new xmldom.DOMParser().parseFromString(
      xpath
        .select(
          "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
          doc
        )[0]
        .toString()
    );
    const sig = new crypto.SignedXml();
    const feidePublicCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.signingCert = feidePublicCert;
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
  });
});
