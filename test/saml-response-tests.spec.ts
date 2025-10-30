import { SignedXml, XMLDSIG_URIS } from "../src";
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
      `/*/*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_URIS.NAMESPACES.ds}']`,
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("test validating SAML response with sha256-rsa-MGF1", function () {
    const xml = fs.readFileSync("./test/static/valid_saml_sha256_rsa_mgf1.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select1(
      `/*/*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_URIS.NAMESPACES.ds}']`,
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/idp_certificate.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
  });

  it("test validating SAML response with sha256-rsa-MGF1 fails for modified file", function () {
    const xml = fs.readFileSync("./test/static/invalid_saml_sha256_rsa_mgf1.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select1(
      `/*/*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_URIS.NAMESPACES.ds}']`,
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/idp_certificate.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);

    expect(result).to.be.false;
  });

  it("test validating wrapped assertion signature", function () {
    const xml = fs.readFileSync("./test/static/valid_saml_signature_wrapping.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const assertion = xpath.select1("//*[local-name(.)='Assertion']", doc);
    isDomNode.assertIsNodeLike(assertion);
    const signature = xpath.select1(
      `//*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_URIS.NAMESPACES.ds}']`,
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
    expect(sig.getSignedReferences().length).to.equal(0);
  });

  it("test validating SAML response where a namespace is defined outside the signed element", function () {
    const xml = fs.readFileSync("./test/static/saml_external_ns.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select1(
      `//*//*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_URIS.NAMESPACES.ds}']`,
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/saml_external_ns.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);
    expect(result).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("test reference id does not contain quotes", function () {
    const xml = fs.readFileSync("./test/static/id_with_quotes.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const assertion = xpath.select1("//*[local-name(.)='Assertion']", doc);
    isDomNode.assertIsNodeLike(assertion);
    const signature = xpath.select1(
      `//*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_URIS.NAMESPACES.ds}']`,
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
      `/*/*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_URIS.NAMESPACES.ds}']`,
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.loadSignature(signature);
    // This doesn't matter, just want to make sure that we don't fail due to unknown algorithm
    expect(() => sig.checkSignature(xml)).to.throw(/^invalid signature/);
    expect(sig.getSignedReferences().length).to.equal(0);
  });

  it("throws an error for a document with no `SignedInfo` node", function () {
    const xml = fs.readFileSync("./test/static/invalid_saml_no_signed_info.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const node = xpath.select1(
      `/*/*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_URIS.NAMESPACES.ds}']`,
      doc,
    );

    isDomNode.assertIsNodeLike(node);
    const sig = new SignedXml();
    const feidePublicCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.publicCert = feidePublicCert;

    expect(() => sig.loadSignature(node)).to.throw("no signed info node found");
  });

  it("test validation ignores an additional wrapped `SignedInfo` node", function () {
    const xml = fs.readFileSync("./test/static/saml_wrapped_signed_info_node.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const assertion = xpath.select1("//*[local-name(.)='Assertion']", doc);
    isDomNode.assertIsNodeLike(assertion);
    const signature = xpath.select1(
      `//*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_URIS.NAMESPACES.ds}']`,
      assertion,
    );
    isDomNode.assertIsNodeLike(signature);

    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/saml_external_ns.pem");
    sig.loadSignature(signature);
    /* eslint-disable-next-line deprecation/deprecation */
    expect(sig.getReferences().length).to.equal(1);
    const checkSignatureResult = sig.checkSignature(xml);
    expect(checkSignatureResult).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("test signature throws if multiple `SignedInfo` nodes are found", function () {
    const xml = fs.readFileSync("./test/static/saml_multiple_signed_info_nodes.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const assertion = xpath.select1("//*[local-name(.)='Assertion'][1]", doc);
    isDomNode.assertIsNodeLike(assertion);
    const signature = xpath.select1(
      `//*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_URIS.NAMESPACES.ds}']`,
      assertion,
    );
    isDomNode.assertIsNodeLike(signature);

    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/saml_external_ns.pem");
    expect(() => sig.loadSignature(signature)).to.throw(
      "could not load signature that contains multiple SignedInfo nodes",
    );
  });

  describe("for a SAML response with a digest value comment", () => {
    it("loads digest value from text content instead of comment", function () {
      const xml = fs.readFileSync("./test/static/valid_saml_with_digest_comment.xml", "utf-8");
      const doc = new xmldom.DOMParser().parseFromString(xml);
      const assertion = xpath.select1("//*[local-name(.)='Assertion']", doc);
      isDomNode.assertIsNodeLike(assertion);
      const signature = xpath.select1(
        `//*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_URIS.NAMESPACES.ds}']`,
        assertion,
      );
      isDomNode.assertIsNodeLike(signature);
      const sig = new SignedXml();
      sig.publicCert = fs.readFileSync("./test/static/feide_public.pem");

      sig.loadSignature(signature);

      /* eslint-disable-next-line deprecation/deprecation */
      expect(sig.getReferences()[0].digestValue).to.equal("RnNjoyUguwze5w2R+cboyTHlkQk=");
      expect(sig.checkSignature(xml)).to.be.false;
      expect(sig.getSignedReferences().length).to.equal(0);
    });
  });
});
