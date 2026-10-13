import { SignedXml } from "../src/index";
import * as fs from "fs";
import { expect } from "chai";

describe("Input that 7.0 rejects, and 6.x still takes", function () {
  it("loads a Reference past a Transform that has no Algorithm", function () {
    const sig = new SignedXml();
    sig.loadSignature(
      '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo>' +
        '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
        '<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>' +
        '<Reference URI="#_0"><Transforms><Transform/>' +
        '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms>' +
        '<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>' +
        "<DigestValue>AAAA</DigestValue></Reference></SignedInfo>" +
        "<SignatureValue>AAAA</SignatureValue></Signature>",
    );

    /* eslint-disable-next-line deprecation/deprecation */
    expect(sig.getReferences().map((reference) => reference.transforms)).to.deep.equal([
      ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    ]);
  });

  it("signs an empty-URI reference to an element that is not the document element", function () {
    const sig = new SignedXml({
      privateKey: fs.readFileSync("./test/static/client.pem"),
      canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    });
    sig.addReference({
      xpath: "//*[local-name(.)='a']",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      isEmptyUri: true,
    });

    sig.computeSignature("<root><a>1</a><b>2</b></root>");

    expect(sig.getSignatureXml()).to.include('<Reference URI="">');
  });
});
