import { expect } from "chai";
import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import {
  C14nCanonicalization,
  C14nCanonicalizationWithComments,
  ExclusiveCanonicalization,
  ExclusiveCanonicalizationWithComments,
  SignedXml,
} from "../src/index";

const canonicalizers = [
  C14nCanonicalization,
  C14nCanonicalizationWithComments,
  ExclusiveCanonicalization,
  ExclusiveCanonicalizationWithComments,
];

describe("processing instructions in signed references", function () {
  for (const Canonicalization of canonicalizers) {
    const algorithm = new Canonicalization().getAlgorithmName();

    it(`rejects text replaced by a processing instruction with ${algorithm}`, function () {
      const signer = new SignedXml({
        privateKey: fs.readFileSync("./test/static/client.pem"),
        canonicalizationAlgorithm: algorithm,
        signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      });
      signer.addReference({
        xpath: "//item",
        transforms: [algorithm],
        digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      });
      signer.computeSignature("<root><item>payload</item></root>");

      const verify = (xml: string) => {
        const verifier = new SignedXml({
          publicCert: fs.readFileSync("./test/static/client_public.pem"),
        });
        verifier.loadSignature(signer.getSignatureXml());
        return verifier.checkSignature(xml);
      };

      const signedXml = signer.getSignedXml();
      expect(verify(signedXml)).to.be.true;
      const tamperedXml = signedXml.replace(">payload</item>", "><?action payload?></item>");
      expect(verify(tamperedXml)).to.be.false;
    });

    it(`preserves processing instruction markup and data with ${algorithm}`, function () {
      const doc = new xmldom.DOMParser().parseFromString(
        "<root><?action a & b?><?empty   ?></root>",
      );

      expect(new Canonicalization().process(doc.documentElement, {})).to.equal(
        "<root><?action a & b?><?empty?></root>",
      );
    });
  }
});
