import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import { expect } from "chai";
import { SignedXml, SignedXmlOptions } from "../src/index";

const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
const envelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

function sign(xml: string, transforms: string[], options: SignedXmlOptions = {}) {
  const signer = new SignedXml({
    ...options,
    privateKey: fs.readFileSync("./test/static/client.pem"),
    canonicalizationAlgorithm: exclusiveC14n,
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  });
  signer.addReference({
    xpath: "//*[local-name(.)='item']",
    transforms,
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  });
  signer.computeSignature(xml);
  return signer.getSignedXml();
}

function verify(signedXml: string, options: SignedXmlOptions = {}) {
  const verifier = new SignedXml({
    ...options,
    publicCert: fs.readFileSync("./test/static/client_public.pem"),
  });
  verifier.loadSignature(
    verifier.findSignatures(new xmldom.DOMParser().parseFromString(signedXml))[0],
  );
  const valid = verifier.checkSignature(signedXml);

  return { valid, signedReferences: verifier.getSignedReferences() };
}

describe("SignedXml constructor options", function () {
  it("reuses the ID in idAttribute when signing and finds it when verifying", function () {
    const options = { idAttribute: "AssertionID" };
    const signedXml = sign(
      '<root><item AssertionID="item-1">trusted</item></root>',
      [exclusiveC14n],
      options,
    );

    const result = verify(signedXml, options);

    expect(result.valid).to.be.true;
    expect(result.signedReferences).to.deep.equal(['<item AssertionID="item-1">trusted</item>']);
  });

  it("applies implicitTransforms when verifying", function () {
    const embedded = sign('<root><item Id="item">trusted</item></root>', [
      envelopedSignature,
    ]).replace("<root>", '<root xmlns:env="urn:envelope">');

    const withoutImplicit = verify(embedded);
    const withImplicit = verify(embedded, { implicitTransforms: [exclusiveC14n] });

    expect(withoutImplicit.valid).to.be.false;
    expect(withImplicit.valid).to.be.true;
    expect(withImplicit.signedReferences).to.deep.equal(['<item Id="item">trusted</item>']);
  });
});
