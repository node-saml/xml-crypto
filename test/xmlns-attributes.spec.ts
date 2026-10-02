import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import { expect } from "chai";
import { SignedXml } from "../src/index";

const inclusiveC14n = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";

describe("attributes whose names begin with xmlns", function () {
  for (const transform of [inclusiveC14n, exclusiveC14n]) {
    it(`rejects changes to an ordinary attribute under ${transform}`, function () {
      const signer = new SignedXml({
        privateKey: fs.readFileSync("./test/static/client.pem"),
        canonicalizationAlgorithm: exclusiveC14n,
        signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      });
      signer.addReference({
        xpath: "//*[local-name(.)='item']",
        transforms: [transform],
        digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      });
      signer.computeSignature('<root><item Id="signed" xmlnsRole="user"/></root>');

      const signedXml = signer.getSignedXml();
      const verifier = new SignedXml({
        publicCert: fs.readFileSync("./test/static/client_public.pem"),
      });
      verifier.loadSignature(
        verifier.findSignatures(new xmldom.DOMParser().parseFromString(signedXml))[0],
      );
      expect(verifier.checkSignature(signedXml)).to.be.true;

      const tamperedXml = signedXml.replace('xmlnsRole="user"', 'xmlnsRole="admin"');
      expect(tamperedXml).not.to.equal(signedXml);
      expect(verifier.checkSignature(tamperedXml)).to.be.false;
      expect(verifier.getSignedReferences()).to.be.empty;
    });
  }
});
