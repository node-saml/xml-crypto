import { SignedXml, XMLDSIG_URIS } from "../src";
import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as fs from "fs";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";

describe("HMAC tests", function () {
  it("test validating HMAC signature", function () {
    const xml = fs.readFileSync("./test/static/hmac_signature.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select1(
      `/*/*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_URIS.NAMESPACES.ds}']`,
      doc,
    );
    isDomNode.assertIsNodeLike(signature);

    const sig = new SignedXml();
    sig.enableHMAC();
    sig.publicCert = fs.readFileSync("./test/static/hmac.key");
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("test HMAC signature with incorrect key", function () {
    const xml = fs.readFileSync("./test/static/hmac_signature.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select1(
      `/*/*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_URIS.NAMESPACES.ds}']`,
      doc,
    );
    isDomNode.assertIsNodeLike(signature);

    const sig = new SignedXml();
    sig.enableHMAC();
    sig.publicCert = fs.readFileSync("./test/static/hmac-foobar.key");
    sig.loadSignature(signature);

    expect(() => sig.checkSignature(xml)).to.throw(/^invalid signature/);
    expect(sig.getSignedReferences().length).to.equal(0);
  });

  it("test create and validate HMAC signature", function () {
    const xml = "<library>" + "<book>" + "<name>Harry Potter</name>" + "</book>" + "</library>";
    const sig = new SignedXml();
    sig.enableHMAC();
    sig.privateKey = fs.readFileSync("./test/static/hmac.key");
    sig.signatureAlgorithm = XMLDSIG_URIS.SIGNATURE_ALGORITHMS.HMAC_SHA1;
    sig.addReference({
      xpath: "//*[local-name(.)='book']",
      digestAlgorithm: XMLDSIG_URIS.HASH_ALGORITHMS.SHA1,
      transforms: [XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N],
    });
    sig.canonicalizationAlgorithm = XMLDSIG_URIS.CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
    sig.computeSignature(xml);

    const doc = new xmldom.DOMParser().parseFromString(sig.getSignedXml());
    const signature = xpath.select1(
      `/*/*[local-name(.)='Signature' and namespace-uri(.)='${XMLDSIG_URIS.NAMESPACES.ds}']`,
      doc,
    );
    isDomNode.assertIsNodeLike(signature);

    const verify = new SignedXml();
    verify.enableHMAC();
    verify.publicCert = fs.readFileSync("./test/static/hmac.key");
    verify.loadSignature(signature);
    const result = verify.checkSignature(sig.getSignedXml());

    expect(result).to.be.true;
    expect(verify.getSignedReferences().length).to.equal(1);
  });
});
