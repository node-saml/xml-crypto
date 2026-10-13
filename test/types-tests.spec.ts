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

  it("invokes the callback once when the callback throws", function () {
    const sig = createSigner(fs.readFileSync("./test/static/client.pem"));

    const errorsSeen: (string | null)[] = [];
    /* eslint-disable-next-line deprecation/deprecation */
    const callback: ErrorFirstCallback<SignedXml> = (err) => {
      errorsSeen.push(err ? err.message : null);
      throw new Error("Error Thrown");
    };

    /* eslint-disable-next-line deprecation/deprecation */
    expect(() => sig.computeSignature(xml, callback)).to.throw("Error Thrown");
    expect(errorsSeen).to.deep.equal([null]);
  });

  it("invokes the callback once, with an error, when signing fails", function () {
    const sig = createSigner(fs.readFileSync("./test/static/client_public.pem"));

    const outcomes: string[] = [];
    /* eslint-disable-next-line deprecation/deprecation */
    sig.computeSignature(xml, (err) => outcomes.push(err ? "error" : "success"));

    expect(outcomes).to.deep.equal(["error"]);
    expect(sig.getSignedXml()).to.equal("");
  });

  it("gives the result of checkSignature() to its callback", function () {
    const sig = new SignedXml({
      privateKey: fs.readFileSync("./test/static/client.pem"),
      canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    });
    sig.addReference({
      xpath: "/*",
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      transforms: [
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        "http://www.w3.org/2001/10/xml-exc-c14n#",
      ],
    });
    sig.computeSignature(xml);
    const verifier = new SignedXml({
      publicCert: fs.readFileSync("./test/static/client_public.pem"),
    });
    verifier.loadSignature(sig.getSignatureXml());

    const results: (boolean | undefined)[] = [];
    /* eslint-disable-next-line deprecation/deprecation */
    verifier.checkSignature(sig.getSignedXml(), (err, isValid) => results.push(isValid));

    expect(results).to.deep.equal([true]);
  });
});
