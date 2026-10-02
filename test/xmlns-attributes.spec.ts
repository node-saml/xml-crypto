import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import { expect } from "chai";
import { findAncestorNs, SignedXml } from "../src/index";
import {
  exclusiveC14n,
  inclusiveC14n,
  rsaSha256,
  sha256,
  verifySignature,
} from "./signature-helpers";

describe("attributes whose names begin with xmlns", function () {
  it("does not treat an ordinary ancestor attribute as a namespace declaration", function () {
    const doc = new xmldom.DOMParser().parseFromString(
      '<root xmlns:p="urn:test" xmlnsRole="user"><item/></root>',
    );

    expect(findAncestorNs(doc, "/root/item")).to.deep.equal([
      { prefix: "p", namespaceURI: "urn:test" },
    ]);
  });

  for (const transform of [inclusiveC14n, exclusiveC14n]) {
    it(`rejects changes to an ordinary attribute under ${transform}`, function () {
      const signer = new SignedXml({
        privateKey: fs.readFileSync("./test/static/client.pem"),
        canonicalizationAlgorithm: exclusiveC14n,
        signatureAlgorithm: rsaSha256,
      });
      signer.addReference({
        xpath: "//*[local-name(.)='item']",
        transforms: [transform],
        digestAlgorithm: sha256,
      });
      signer.computeSignature('<root><item Id="signed" xmlnsRole="user"/></root>');

      const signedXml = signer.getSignedXml();
      expect(verifySignature(signedXml).valid).to.be.true;

      const tamperedXml = signedXml.replace('xmlnsRole="user"', 'xmlnsRole="admin"');
      expect(tamperedXml).not.to.equal(signedXml);
      const result = verifySignature(tamperedXml);
      expect(result.valid).to.be.false;
      expect(result.signedReferences).to.be.empty;
    });
  }
});
