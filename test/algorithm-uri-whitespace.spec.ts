import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import { expect } from "chai";
import { SignedXml } from "../src/index";

const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
const rsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const algorithms = {
  canonicalization: exclusiveC14n,
  transform: exclusiveC14n,
  signature: rsaSha256,
  digest: sha256,
};

const padded = (algorithm: string) => `${algorithm} `;

function sign(signedWith: typeof algorithms): string {
  const signer = new SignedXml({
    privateKey: fs.readFileSync("./test/static/client.pem"),
    canonicalizationAlgorithm: signedWith.canonicalization,
    signatureAlgorithm: signedWith.signature,
  });
  // The signer writes each Algorithm from getAlgorithmName(), so these let it sign a padded one.
  const ExclusiveC14n = signer.CanonicalizationAlgorithms[exclusiveC14n];
  const RsaSha256 = signer.SignatureAlgorithms[rsaSha256];
  const Sha256 = signer.HashAlgorithms[sha256];
  signer.CanonicalizationAlgorithms[padded(exclusiveC14n)] = class extends ExclusiveC14n {
    getAlgorithmName = () => padded(exclusiveC14n);
  };
  signer.SignatureAlgorithms[padded(rsaSha256)] = class extends RsaSha256 {
    getAlgorithmName = () => padded(rsaSha256);
  };
  signer.HashAlgorithms[padded(sha256)] = class extends Sha256 {
    getAlgorithmName = () => padded(sha256);
  };
  signer.addReference({
    xpath: "//*[local-name(.)='book']",
    transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", signedWith.transform],
    digestAlgorithm: signedWith.digest,
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
  for (const [element, name, kind] of [
    ["CanonicalizationMethod", "canonicalization", "canonicalization"],
    ["Transform", "transform", "canonicalization"],
    ["SignatureMethod", "signature", "signature"],
    ["DigestMethod", "digest", "hash"],
  ] as const) {
    it(`rejects a ${element} Algorithm signed with whitespace around it`, function () {
      const algorithm = padded(algorithms[name]);
      const xml = sign({ ...algorithms, [name]: algorithm });

      expect(() => checkSignature(xml)).to.throw(
        `${kind} algorithm '${algorithm}' is not supported`,
      );
    });
  }
});
