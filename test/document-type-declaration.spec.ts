import { SignedXml } from "../src/index";
import * as fs from "fs";
import { expect } from "chai";

describe("A document with a DOCTYPE, which 7.0 refuses", function () {
  it("is still signed and verified, without the default attribute it declares", function () {
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
    sig.computeSignature(
      '<!DOCTYPE root [<!ATTLIST root role CDATA "admin">]><root>content</root>',
    );
    const signedXml = sig.getSignedXml();

    const verifier = new SignedXml({
      publicCert: fs.readFileSync("./test/static/client_public.pem"),
    });
    verifier.loadSignature(sig.getSignatureXml());

    expect(signedXml).to.include("<!DOCTYPE root>");
    expect(signedXml).to.not.include("role");
    expect(verifier.checkSignature(signedXml)).to.be.true;
  });
});
