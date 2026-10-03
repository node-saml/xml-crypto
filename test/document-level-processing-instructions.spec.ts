import { expect } from "chai";
import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import { SignedXml } from "../src/index";

const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
const envelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

describe("document-level processing instructions in an empty-URI reference", function () {
  for (const { description, transforms } of [
    {
      description: "enveloped signature before canonicalization",
      transforms: [envelopedSignature, exclusiveC14n],
    },
    {
      description: "canonicalization before enveloped signature",
      transforms: [exclusiveC14n, envelopedSignature],
    },
  ]) {
    it(`rejects a changed stylesheet instruction with ${description}`, function () {
      const signer = new SignedXml({
        privateKey: fs.readFileSync("./test/static/client.pem"),
        canonicalizationAlgorithm: exclusiveC14n,
        signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      });
      signer.addReference({
        xpath: "/*",
        isEmptyUri: true,
        transforms,
        digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      });
      signer.computeSignature(
        '<?xml-stylesheet type="text/xsl" href="https://example.com/trusted.xsl"?>\n<root><item>trusted</item></root>',
      );

      const verify = (xml: string) => {
        const verifier = new SignedXml({
          publicCert: fs.readFileSync("./test/static/client_public.pem"),
        });
        const doc = new xmldom.DOMParser().parseFromString(xml);
        verifier.loadSignature(verifier.findSignatures(doc)[0]);
        return verifier.checkSignature(xml);
      };

      const signedXml = signer.getSignedXml();
      expect(verify(signedXml)).to.be.true;

      const tamperedXml = signedXml.replace("trusted.xsl", "attacker.xsl");
      expect(tamperedXml).not.to.equal(signedXml);
      expect(verify(tamperedXml)).to.be.false;
    });
  }
});
