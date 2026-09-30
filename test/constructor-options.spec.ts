import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";
import { SignedXml, SignedXmlOptions } from "../src/index";

const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";

function sign(xml: string, options: SignedXmlOptions = {}) {
  const signer = new SignedXml({
    ...options,
    privateKey: fs.readFileSync("./test/static/client.pem"),
    canonicalizationAlgorithm: exclusiveC14n,
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  });
  signer.addReference({
    xpath: "//*[local-name(.)='item']",
    transforms: [exclusiveC14n],
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  });
  signer.computeSignature(xml);
  return signer.getSignedXml();
}

function verify(
  signedXml: string,
  options: SignedXmlOptions = {},
  configure?: (verifier: SignedXml) => void,
) {
  const verifier = new SignedXml({
    ...options,
    publicCert: fs.readFileSync("./test/static/client_public.pem"),
  });
  configure?.(verifier);
  verifier.loadSignature(
    verifier.findSignatures(new xmldom.DOMParser().parseFromString(signedXml))[0],
  );
  const valid = verifier.checkSignature(signedXml);

  return { valid, signedReferences: verifier.getSignedReferences() };
}

describe("SignedXml constructor options", function () {
  it("reuses the ID in idAttribute when signing and finds it when verifying", function () {
    const options = { idAttribute: "AssertionID" };
    const signedXml = sign('<root><item AssertionID="item-1">trusted</item></root>', options);

    const result = verify(signedXml, options);

    expect(result.valid).to.be.true;
    expect(result.signedReferences).to.deep.equal(['<item AssertionID="item-1">trusted</item>']);
  });

  it("applies implicitTransforms when verifying", function () {
    const stripNote = "urn:xml-crypto:test:strip-note";
    class StripNote {
      process(node: Node) {
        isDomNode.assertIsElementNode(node);
        node.removeAttribute("note");
        return node;
      }

      getAlgorithmName() {
        return stripNote;
      }
    }
    const registerStripNote = (verifier: SignedXml) => {
      verifier.CanonicalizationAlgorithms[stripNote] = StripNote;
    };
    const annotated = sign('<root><item Id="item">trusted</item></root>').replace(
      '<item Id="item">',
      '<item Id="item" note="added">',
    );

    const withoutImplicit = verify(annotated, {}, registerStripNote);
    const withImplicit = verify(annotated, { implicitTransforms: [stripNote] }, registerStripNote);

    expect(withoutImplicit.valid).to.be.false;
    expect(withImplicit.valid).to.be.true;
  });
});
