import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import { expect } from "chai";
import { SignedXml } from "../src/index";

const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
const inclusiveC14n = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const rsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

function verify(xml: string): boolean {
  const verifier = new SignedXml({
    publicCert: fs.readFileSync("./test/static/client_public.pem"),
  });
  const doc = new xmldom.DOMParser().parseFromString(xml);
  verifier.loadSignature(verifier.findSignatures(doc)[0]);
  return verifier.checkSignature(xml);
}

describe("inherited context in signed references", function () {
  it("protects the default namespace requested by an exclusive C14N PrefixList", function () {
    const signer = new SignedXml({
      privateKey: fs.readFileSync("./test/static/client.pem"),
      canonicalizationAlgorithm: exclusiveC14n,
      signatureAlgorithm: rsaSha256,
    });
    signer.addReference({
      xpath: "//*[local-name(.)='item']",
      transforms: [exclusiveC14n],
      digestAlgorithm: sha256,
      inclusiveNamespacesPrefixList: ["#default"],
    });
    signer.computeSignature(
      '<root><p:item xmlns:p="urn:item" xmlns="urn:trusted" type="Role">value</p:item></root>',
    );

    const signedXml = signer.getSignedXml();
    expect(verify(signedXml)).to.be.true;

    const tamperedXml = signedXml.replace('xmlns="urn:trusted"', 'xmlns="urn:attacker"');
    expect(tamperedXml).not.to.equal(signedXml);
    expect(verify(tamperedXml)).to.be.false;
  });

  it("protects inherited xml:lang under inclusive C14N", function () {
    const signer = new SignedXml({
      privateKey: fs.readFileSync("./test/static/client.pem"),
      canonicalizationAlgorithm: exclusiveC14n,
      signatureAlgorithm: rsaSha256,
    });
    signer.addReference({
      xpath: "//*[local-name(.)='item']",
      transforms: [inclusiveC14n],
      digestAlgorithm: sha256,
    });
    signer.computeSignature('<root xml:lang="en"><item>value</item></root>');

    const signedXml = signer.getSignedXml();
    expect(verify(signedXml)).to.be.true;

    const tamperedXml = signedXml.replace('xml:lang="en"', 'xml:lang="fr"');
    expect(tamperedXml).not.to.equal(signedXml);
    expect(verify(tamperedXml)).to.be.false;
  });
});
