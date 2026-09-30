import * as fs from "fs";
import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";
import { SignedXml } from "../src/index";

const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
const envelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const rsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";

function createSigner() {
  const signer = new SignedXml({
    privateKey: fs.readFileSync("./test/static/client.pem"),
    canonicalizationAlgorithm: exclusiveC14n,
    signatureAlgorithm: rsaSha256,
  });
  signer.addReference({
    xpath: "/*",
    transforms: [envelopedSignature, exclusiveC14n],
    digestAlgorithm: sha256,
  });
  return signer;
}

describe("signature location errors", function () {
  for (const action of ["before", "after"] as const) {
    it(`reports the root element for ${action}`, function () {
      const signer = createSigner();

      expect(() =>
        signer.computeSignature("<root><a>trusted</a></root>", {
          location: { reference: "/*", action },
        }),
      ).to.throw(
        "`location.reference` refers to the root element, so we can't insert `" + action + "`",
      );
    });

    it(`reports a parentless attribute for ${action}`, function () {
      const signer = createSigner();

      expect(() =>
        signer.computeSignature('<root id="x"><a>trusted</a></root>', {
          location: { reference: "//@id", action },
        }),
      ).to.throw(
        "`location.reference` selects a node without a parent, so we can't insert `" + action + "`",
      );
    });

    it(`reports a document-level processing instruction for ${action}`, function () {
      const signer = createSigner();

      expect(() =>
        signer.computeSignature("<?pi data?><root><a>trusted</a></root>", {
          location: { reference: "/processing-instruction()", action },
        }),
      ).to.throw(
        "`location.reference` selects a document-level node, so we can't insert `" +
          action +
          "`",
      );
    });

    it(`still accepts a text node for ${action}`, function () {
      const signer = createSigner();
      signer.computeSignature("<root><a>trusted</a>text</root>", {
        location: { reference: "/root/text()", action },
      });
      const signedXml = signer.getSignedXml();

      const doc = new xmldom.DOMParser().parseFromString(signedXml);
      const signature = xpath.select1(
        "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
        doc,
      );
      isDomNode.assertIsNodeLike(signature);

      const verifier = new SignedXml({
        publicCert: fs.readFileSync("./test/static/client_public.pem"),
      });
      verifier.loadSignature(signature);

      expect(verifier.checkSignature(signedXml)).to.be.true;
    });
  }
});
