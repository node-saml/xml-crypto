import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import { expect } from "chai";
import { SignedXml } from "../src/index";

const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
const rsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";

function sign(): string {
  const signer = new SignedXml({
    privateKey: fs.readFileSync("./test/static/client.pem"),
    canonicalizationAlgorithm: exclusiveC14n,
    signatureAlgorithm: rsaSha256,
  });
  signer.addReference({
    xpath: "//*[local-name(.)='book']",
    transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", exclusiveC14n],
    digestAlgorithm: sha256,
  });
  signer.computeSignature("<library><book Id='b1'><title>Harry Potter</title></book></library>");
  return signer.getSignedXml();
}

function checkSignature(xml: string): boolean {
  const verifier = new SignedXml({
    publicCert: fs.readFileSync("./test/static/client_public.pem"),
  });
  verifier.loadSignature(verifier.findSignatures(new xmldom.DOMParser().parseFromString(xml))[0]);
  return verifier.checkSignature(xml);
}

describe("Algorithm attributes", function () {
  for (const [element, uri, kind] of [
    ["CanonicalizationMethod", exclusiveC14n, "canonicalization"],
    ["Transform", exclusiveC14n, "canonicalization"],
    ["SignatureMethod", rsaSha256, "signature"],
    ["DigestMethod", sha256, "hash"],
  ]) {
    it(`rejects a ${element} Algorithm with whitespace around it`, function () {
      const xml = sign().replace(
        `<${element} Algorithm="${uri}"/>`,
        `<${element} Algorithm="${uri} "/>`,
      );

      expect(() => checkSignature(xml)).to.throw(`${kind} algorithm '${uri} ' is not supported`);
    });
  }
});
