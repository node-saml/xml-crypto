import { SignedXml } from "../src/index";
import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as fs from "fs";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";

describe("SAML response tests", function () {
  it("test validating SAML response", function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select1(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
  });

  it("test validating wrapped assertion signature", function () {
    const xml = fs.readFileSync("./test/static/valid_saml_signature_wrapping.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const assertion = xpath.select1("//*[local-name(.)='Assertion']", doc);
    isDomNode.assertIsNodeLike(assertion);
    const signature = xpath.select1(
      "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      assertion,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.loadSignature(signature);
    expect(
      function () {
        sig.checkSignature(xml);
      },
      "Should not validate a document which contains multiple elements with the " +
        "same value for the ID / Id / Id attributes, in order to prevent " +
        "signature wrapping attack.",
    ).to.throw();
  });

  it("test validating SAML response where a namespace is defined outside the signed element", function () {
    const xml = fs.readFileSync("./test/static/saml_external_ns.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select1(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/saml_external_ns.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);
    expect(result).to.be.true;
  });

  it("test reference id does not contain quotes", function () {
    const xml = fs.readFileSync("./test/static/id_with_quotes.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const assertion = xpath.select1("//*[local-name(.)='Assertion']", doc);
    isDomNode.assertIsNodeLike(assertion);
    const signature = xpath.select1(
      "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      assertion,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.loadSignature(signature);
    expect(function () {
      sig.checkSignature(xml);
    }, "id should not contain quotes").to.throw();
  });

  it("test validating SAML response WithComments", function () {
    const xml = fs.readFileSync("./test/static/valid_saml_withcomments.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select1(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.loadSignature(signature);
    // This doesn't matter, just want to make sure that we don't fail due to unknown algorithm
    expect(() => sig.checkSignature(xml)).to.throw(/^invalid signature/);
  });
});
