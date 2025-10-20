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
});
