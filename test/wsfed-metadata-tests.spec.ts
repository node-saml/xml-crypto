import { SignedXml } from "../src/index";
import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as fs from "fs";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";

describe("WS-Fed Metadata tests", function () {
  it("test validating WS-Fed Metadata", function () {
    const xml = fs.readFileSync("./test/static/wsfederation_metadata.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = xpath.select1(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/wsfederation_metadata.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
  });
});
