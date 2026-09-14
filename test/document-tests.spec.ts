import { SignedXml } from "../src/index";
import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as fs from "fs";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";

describe("Document tests", function () {
  it("test with a document (using FileKeyInfo)", function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const node = xpath.select1(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );

    isDomNode.assertIsNodeLike(node);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.loadSignature(node);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("test with a document (using StringKeyInfo)", function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const node = xpath.select1(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );

    isDomNode.assertIsNodeLike(node);
    const sig = new SignedXml();
    const feidePublicCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.publicCert = feidePublicCert;
    sig.loadSignature(node);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);
  });
});

describe("Signed reference tests", function () {
  it("should read signed data from the signed references", function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const sig = new SignedXml();
    sig.getCertFromKeyInfo = SignedXml.getCertFromKeyInfo;
    sig.loadSignature(sig.findSignatures(doc)[0]);
    expect(sig.checkSignature(xml)).to.be.true;

    const signedDoc = new xmldom.DOMParser().parseFromString(sig.getSignedReferences()[0]);
    const mail = xpath.select1(
      "//*[local-name()='Attribute' and @Name='mail']/*[local-name()='AttributeValue']/text()",
      signedDoc,
    );
    isDomNode.assertIsNodeLike(mail);
    expect(mail.nodeValue).to.equal("henri.bergius@nemein.com");
  });
});
