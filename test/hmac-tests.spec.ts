import { SignedXml } from "../src/index";
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
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);

    const sig = new SignedXml();
    sig.enableHMAC();
    sig.publicCert = fs.readFileSync("./test/static/hmac.key");
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
  });

  it("test HMAC signature with incorrect key", function () {
    const xml = fs.readFileSync("./test/static/hmac_signature.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select1(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);

    const sig = new SignedXml();
    sig.enableHMAC();
    sig.publicCert = fs.readFileSync("./test/static/hmac-foobar.key");
    sig.loadSignature(signature);

    expect(() => sig.checkSignature(xml)).to.throw(/^invalid signature/);
  });

  it("test create and validate HMAC signature", function () {
    const xml = "<library>" + "<book>" + "<name>Harry Potter</name>" + "</book>" + "</library>";
    const sig = new SignedXml();
    sig.enableHMAC();
    sig.privateKey = fs.readFileSync("./test/static/hmac.key");
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
    sig.addReference({
      xpath: "//*[local-name(.)='book']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });
    sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sig.computeSignature(xml);

    const doc = new xmldom.DOMParser().parseFromString(sig.getSignedXml());
    const signature = xpath.select1(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);

    const verify = new SignedXml();
    verify.enableHMAC();
    verify.publicCert = fs.readFileSync("./test/static/hmac.key");
    verify.loadSignature(signature);
    const result = verify.checkSignature(sig.getSignedXml());

    expect(result).to.be.true;
  });
});
