const select = require("xpath").select;
const dom = require("@xmldom/xmldom").DOMParser;
const SignedXml = require("../lib/signed-xml.js").SignedXml;
const fs = require("fs");
const expect = require("chai").expect;

describe("KeyInfo tests", function () {
  it("adds X509Certificate element during signature", function () {
    const xml = "<root><x /></root>";
    const sig = new SignedXml();
    sig.signingKey = fs.readFileSync("./test/static/client.pem");
    sig.signingCert = fs.readFileSync("./test/static/client_public.pem");
    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();
    const doc = new dom().parseFromString(signedXml);
    const x509 = select("//*[local-name(.)='X509Certificate']", doc.documentElement);
    expect(x509.length, "X509Certificate element should exist").to.equal(1);
  });
});
