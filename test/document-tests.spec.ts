import { SignedXml } from "../src/index";
import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as fs from "fs";
import { expect } from "chai";

describe("Document tests", function () {
  it("test with a document (using FileKeyInfo)", function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = new xmldom.DOMParser().parseFromString(
      // @ts-expect-error FIXME
      xpath
        .select(
          "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
          doc
        )[0]
        .toString()
    );
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
  });

  it("test with a document (using StringKeyInfo)", function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = new xmldom.DOMParser().parseFromString(
      // @ts-expect-error FIXME
      xpath
        .select(
          "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
          doc
        )[0]
        .toString()
    );
    const sig = new SignedXml();
    const feidePublicCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.publicCert = feidePublicCert;
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
  });
});
