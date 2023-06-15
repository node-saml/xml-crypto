const crypto = require("../index");
const xpath = require("xpath");
const xmldom = require("@xmldom/xmldom");
const fs = require("fs");
const expect = require("chai").expect;

describe("SAML response tests", function () {
  it("test validating SAML response", function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )[0];
    const sig = new crypto.SignedXml();
    sig.signingCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
  });

  it("test validating wrapped assertion signature", function () {
    const xml = fs.readFileSync("./test/static/valid_saml_signature_wrapping.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const assertion = xpath.select("//*[local-name(.)='Assertion']", doc)[0];
    const signature = xpath.select(
      "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      assertion
    )[0];
    const sig = new crypto.SignedXml();
    sig.signingCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.loadSignature(signature);
    expect(function () {
      sig.checkSignature(xml);
    }, "Should not validate a document which contains multiple elements with the " +
      "same value for the ID / Id / Id attributes, in order to prevent " +
      "signature wrapping attack.").to.throw();
  });

  it("test validating SAML response where a namespace is defined outside the signed element", function () {
    const xml = fs.readFileSync("./test/static/saml_external_ns.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )[0];
    const sig = new crypto.SignedXml();
    sig.signingCert = fs.readFileSync("./test/static/saml_external_ns.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);
    expect(result).to.be.true;
  });

  it("test reference id does not contain quotes", function () {
    const xml = fs.readFileSync("./test/static/id_with_quotes.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const assertion = xpath.select("//*[local-name(.)='Assertion']", doc)[0];
    const signature = xpath.select(
      "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      assertion
    )[0];
    const sig = new crypto.SignedXml();
    sig.signingCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.loadSignature(signature);
    expect(function () {
      sig.checkSignature(xml);
    }, "id should not contain quotes").to.throw();
  });

  it("test validating SAML response WithComments", function () {
    const xml = fs.readFileSync("./test/static/valid_saml_withcomments.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )[0];
    const sig = new crypto.SignedXml();
    sig.signingCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);
    // This doesn't matter, just want to make sure that we don't fail due to unknown algorithm
    expect(result).to.be.false;
  });
});
