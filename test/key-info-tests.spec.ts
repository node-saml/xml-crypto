import * as xmldom from "@xmldom/xmldom";
import * as fs from "fs";
import * as xpath from "xpath";
import { SignedXml } from "../src/index";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";

describe("KeyInfo tests", function () {
  it("adds X509Certificate element during signature", function () {
    const xml = "<root><x /></root>";
    const sig = new SignedXml();
    sig.privateKey = fs.readFileSync("./test/static/client.pem");
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");
    sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();
    const doc = new xmldom.DOMParser().parseFromString(signedXml);
    const x509 = xpath.select("//*[local-name(.)='X509Certificate']", doc.documentElement);
    isDomNode.assertIsArrayOfNodes(x509);

    expect(x509.length, "X509Certificate element should exist").to.equal(1);
  });

  it("make sure private hmac key is not leaked due to key confusion", function () {
    const xml = "<library>" + "<book>" + "<name>Harry Potter</name>" + "</book>" + "</library>";
    const sig = new SignedXml();
    sig.privateKey = fs.readFileSync("./test/static/hmac.key");
    sig.publicCert = fs.readFileSync("./test/static/hmac.key");
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
    sig.enableHMAC();
    sig.addReference({
      xpath: "//*[local-name(.)='book']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });
    sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sig.computeSignature(xml);

    const doc = new xmldom.DOMParser().parseFromString(sig.getSignedXml());
    const keyInfo = xpath.select1("//*[local-name(.)='KeyInfo']", doc);

    expect(keyInfo).to.be.undefined;
  });

  it("passes getCertFromKeyInfo the Signature's own KeyInfo, not one inside an Object", function () {
    const sig = new SignedXml({
      privateKey: fs.readFileSync("./test/static/client.pem"),
      canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    });
    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    });
    sig.computeSignature("<root><x /></root>");
    const signedXml = sig
      .getSignedXml()
      .replace(
        "</Signature>",
        "<Object><KeyInfo><KeyName>nested</KeyName></KeyInfo></Object></Signature>",
      );

    const keyInfos: (Node | null | undefined)[] = [];
    const verifier = new SignedXml({
      publicCert: fs.readFileSync("./test/static/client_public.pem"),
      getCertFromKeyInfo: (keyInfo) => {
        keyInfos.push(keyInfo);
        return null;
      },
    });
    verifier.loadSignature(
      verifier.findSignatures(new xmldom.DOMParser().parseFromString(signedXml))[0],
    );

    expect(verifier.checkSignature(signedXml)).to.be.true;
    expect(keyInfos.map((keyInfo) => keyInfo?.toString() ?? null)).to.deep.equal([null]);
  });
});
