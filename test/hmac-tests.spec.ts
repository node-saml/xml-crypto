import { SignedXml } from "../src/index";
import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as fs from "fs";
import { expect } from "chai";

describe("HMAC tests", function () {
  it("test validating HMAC signature", function () {
    const xml = fs.readFileSync("./test/static/hmac_signature.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select1(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    );
    const sig = new SignedXml();
    sig.enableHMAC();
    sig.publicCert = fs.readFileSync("./test/static/hmac.key");
    // @ts-expect-error FIXME
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
  });

  it("test HMAC signature with incorrect key", function () {
    const xml = fs.readFileSync("./test/static/hmac_signature.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select1(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    );
    const sig = new SignedXml();
    sig.enableHMAC();
    sig.publicCert = fs.readFileSync("./test/static/hmac-foobar.key");
    // @ts-expect-error FIXME
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);

    expect(result).to.be.false;
  });

  it("test create and validate HMAC signature", function () {
    const xml = "<library>" + "<book>" + "<name>Harry Potter</name>" + "</book>" + "</library>";
    const sig = new SignedXml();
    sig.enableHMAC();
    sig.privateKey = fs.readFileSync("./test/static/hmac.key");
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
    sig.addReference({ xpath: "//*[local-name(.)='book']" });
    sig.computeSignature(xml);

    const doc = new xmldom.DOMParser().parseFromString(sig.getSignedXml());
    const signature = xpath.select1(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    );
    const verify = new SignedXml();
    verify.enableHMAC();
    verify.publicCert = fs.readFileSync("./test/static/hmac.key");
    // @ts-expect-error FIXME
    verify.loadSignature(signature);
    const result = verify.checkSignature(sig.getSignedXml());

    expect(result).to.be.true;
  });
});
