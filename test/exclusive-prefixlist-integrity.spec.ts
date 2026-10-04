import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import { expect } from "chai";
import { SignedXml } from "../src/index";

const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";

function verify(xml: string): boolean {
  const verifier = new SignedXml({
    publicCert: fs.readFileSync("./test/static/client_public.pem"),
  });
  const doc = new xmldom.DOMParser().parseFromString(xml);
  verifier.loadSignature(verifier.findSignatures(doc)[0]);
  return verifier.checkSignature(xml);
}

describe("exclusive canonicalization PrefixList integrity", function () {
  it("rejects a namespace declaration impersonated by an ordinary prefixed attribute", function () {
    const signer = new SignedXml({
      privateKey: fs.readFileSync("./test/static/client.pem"),
      canonicalizationAlgorithm: exclusiveC14n,
      signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    });
    signer.addReference({
      xpath: "//*[local-name(.)='item']",
      transforms: [exclusiveC14n],
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      inclusiveNamespacesPrefixList: ["bar"],
    });
    signer.computeSignature(
      '<root><item xmlns:foo="urn:foo" foo:bar="urn:value" type="bar:Admin"/></root>',
    );

    const signedXml = signer.getSignedXml();
    expect(verify(signedXml)).to.be.true;

    const tamperedXml = signedXml.replace(
      'type="bar:Admin"',
      'xmlns:bar="urn:value" type="bar:Admin"',
    );
    expect(tamperedXml).not.to.equal(signedXml);
    expect(verify(tamperedXml)).to.be.false;
  });
});
