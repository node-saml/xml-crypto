import * as fs from "fs";
import { expect } from "chai";
import { SignedXml } from "../src/index";
import { exclusiveC14n, rsaSha256, sha256, verifySignature } from "./signature-helpers";

describe("exclusive canonicalization PrefixList integrity", function () {
  it("rejects a namespace declaration impersonated by an ordinary prefixed attribute", function () {
    const signer = new SignedXml({
      privateKey: fs.readFileSync("./test/static/client.pem"),
      canonicalizationAlgorithm: exclusiveC14n,
      signatureAlgorithm: rsaSha256,
    });
    signer.addReference({
      xpath: "//*[local-name(.)='item']",
      transforms: [exclusiveC14n],
      digestAlgorithm: sha256,
      inclusiveNamespacesPrefixList: ["bar"],
    });
    signer.computeSignature(
      '<root><item xmlns:foo="urn:foo" foo:bar="urn:value" type="bar:Admin"/></root>',
    );

    const signedXml = signer.getSignedXml();
    expect(verifySignature(signedXml).valid).to.be.true;

    const tamperedXml = signedXml.replace(
      'type="bar:Admin"',
      'xmlns:bar="urn:value" type="bar:Admin"',
    );
    expect(tamperedXml).not.to.equal(signedXml);
    expect(verifySignature(tamperedXml).valid).to.be.false;
  });
});
