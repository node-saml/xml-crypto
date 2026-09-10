import { SignedXml, type ErrorFirstCallback } from "../src/index";
import * as fs from "fs";
import { expect } from "chai";

describe("Callback invocation", function () {
  const xml = `<x xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' Id='_1'></x>`;

  function createSigner(privateKey: Buffer): SignedXml {
    const sig = new SignedXml();
    sig.privateKey = privateKey;
    sig.addReference({
      xpath: "//*[local-name(.)='x']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });
    sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    return sig;
  }

  // https://github.com/node-saml/xml-crypto/issues/527
  it("invokes the callback once when the callback throws", function () {
    const sig = createSigner(fs.readFileSync("./test/static/client.pem"));

    const errorsSeen: (string | null)[] = [];
    const callback: ErrorFirstCallback<SignedXml> = (err) => {
      errorsSeen.push(err ? err.message : null);
      throw new Error("Error Thrown");
    };

    expect(() => sig.computeSignature(xml, callback)).to.throw("Error Thrown");
    expect(errorsSeen).to.deep.equal([null]);
  });

  it("invokes the callback once, with an error, when signing fails", function () {
    const sig = createSigner(fs.readFileSync("./test/static/client_public.pem"));

    const outcomes: string[] = [];
    sig.computeSignature(xml, (err) => outcomes.push(err ? "error" : "success"));

    expect(outcomes).to.deep.equal(["error"]);
    expect(sig.getSignedXml()).to.equal("");
  });
});
