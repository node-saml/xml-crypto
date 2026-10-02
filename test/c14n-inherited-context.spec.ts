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
      '<root><p:item xmlns:p="urn:item" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="urn:trusted" xsi:type="Role">value</p:item></root>',
    );

    const signedXml = signer.getSignedXml();
    expect(signedXml).to.include('PrefixList="#default"');
    expect(verify(signedXml)).to.be.true;

    const tamperedXml = signedXml.replace('xmlns="urn:trusted"', 'xmlns="urn:attacker"');
    expect(tamperedXml).not.to.equal(signedXml);
    expect(verify(tamperedXml)).to.be.false;
  });

  it("protects a default namespace inherited by a prefixed reference", function () {
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
      '<root xmlns="urn:trusted"><p:item xmlns:p="urn:item" type="Role">value</p:item></root>',
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

  it("protects inherited xml:lang when SignedInfo uses inclusive C14N", function () {
    const signer = new SignedXml({
      privateKey: fs.readFileSync("./test/static/client.pem"),
      canonicalizationAlgorithm: inclusiveC14n,
      signatureAlgorithm: rsaSha256,
    });
    signer.addReference({
      xpath: "//*[local-name(.)='item']",
      transforms: [exclusiveC14n],
      digestAlgorithm: sha256,
    });
    signer.computeSignature('<root xml:lang="en"><item>value</item></root>');

    const signedXml = signer.getSignedXml();
    expect(verify(signedXml)).to.be.true;

    const tamperedXml = signedXml.replace('xml:lang="en"', 'xml:lang="fr"');
    expect(tamperedXml).not.to.equal(signedXml);
    expect(() => verify(tamperedXml)).to.throw(/invalid signature/);
  });
  it("rejects a default namespace added to a prefixed reference", function () {
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
    signer.computeSignature('<root><p:item xmlns:p="urn:item">value</p:item></root>');

    const signedXml = signer.getSignedXml();
    expect(verify(signedXml)).to.be.true;

    const tamperedXml = signedXml.replace(
      'xmlns:p="urn:item"',
      'xmlns="urn:attacker" xmlns:p="urn:item"',
    );
    expect(tamperedXml).not.to.equal(signedXml);
    expect(verify(tamperedXml)).to.be.false;
  });

  it("keeps an element's own xml:lang over its ancestor's value", function () {
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
    signer.computeSignature('<root xml:lang="en"><item xml:lang="fr">value</item></root>');

    const signedXml = signer.getSignedXml();
    expect(verify(signedXml)).to.be.true;

    const changedAncestor = signedXml.replace('xml:lang="en"', 'xml:lang="de"');
    expect(changedAncestor).not.to.equal(signedXml);
    expect(verify(changedAncestor)).to.be.true;

    const changedElement = signedXml.replace('xml:lang="fr"', 'xml:lang="de"');
    expect(changedElement).not.to.equal(signedXml);
    expect(verify(changedElement)).to.be.false;
  });
  it("canonicalizes inherited xml:lang through getCanonXml", function () {
    const doc = new xmldom.DOMParser().parseFromString(
      '<root xml:lang="en"><item>value</item></root>',
    );
    const item = doc.getElementsByTagName("item")[0];

    expect(new SignedXml().getCanonXml([inclusiveC14n], item)).to.equal(
      '<item xml:lang="en">value</item>',
    );
  });
  it("keeps a local default namespace over an ancestor's value", function () {
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
      '<root xmlns="urn:ancestor"><p:item xmlns:p="urn:item" xmlns="urn:local">value</p:item></root>',
    );

    const signedXml = signer.getSignedXml();
    expect(verify(signedXml)).to.be.true;

    const changedAncestor = signedXml.replace('xmlns="urn:ancestor"', 'xmlns="urn:other"');
    expect(changedAncestor).not.to.equal(signedXml);
    expect(verify(changedAncestor)).to.be.true;

    const changedElement = signedXml.replace('xmlns="urn:local"', 'xmlns="urn:other"');
    expect(changedElement).not.to.equal(signedXml);
    expect(verify(changedElement)).to.be.false;
  });
  it("retains the default namespace on prefixed descendants until explicitly reset", function () {
    const doc = new xmldom.DOMParser().parseFromString(
      '<p:item xmlns:p="urn:item" xmlns="urn:default"><p:child>one</p:child><p:empty xmlns="">two</p:empty></p:item>',
    );

    expect(
      new SignedXml().getCanonXml([exclusiveC14n], doc.documentElement, {
        inclusiveNamespacesPrefixList: ["#default"],
      }),
    ).to.equal(
      '<p:item xmlns="urn:default" xmlns:p="urn:item"><p:child>one</p:child><p:empty xmlns="">two</p:empty></p:item>',
    );
  });
});
