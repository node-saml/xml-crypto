import * as crypto from "crypto";
import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import * as xpath from "xpath";
import * as isDomNode from "@xmldom/is-dom-node";
import { expect } from "chai";
import { SignedXml, pemToDer } from "../src/index";

const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

function signerFor(privateKey: crypto.KeyLike | Uint8Array): SignedXml {
  const sig = new SignedXml();
  sig.privateKey = privateKey;
  sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
  sig.signatureAlgorithm = RSA_SHA256;
  sig.addReference({
    xpath: "//*[local-name(.)='x']",
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
  });
  return sig;
}

function verify(signedXml: string): boolean {
  const doc = new xmldom.DOMParser().parseFromString(signedXml);
  const node = xpath.select1(
    "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    doc,
  );
  isDomNode.assertIsNodeLike(node);
  const sig = new SignedXml();
  sig.publicCert = fs.readFileSync("./test/static/client_public.pem");
  sig.loadSignature(node);
  return sig.checkSignature(signedXml);
}

describe("Key material accepted by the bundled algorithms", function () {
  const xml = '<root><x attr="value"></x></root>';

  it("signs and verifies with a private key given as a Uint8Array", function () {
    const pem = fs.readFileSync("./test/static/client.pem");
    const sig = signerFor(new Uint8Array(pem));
    sig.computeSignature(xml);

    expect(verify(sig.getSignedXml())).to.be.true;
  });

  it("refuses a Web Crypto key rather than signing through the DEP0203 shim", async function () {
    const cryptoKey = await crypto.webcrypto.subtle.importKey(
      "pkcs8",
      pemToDer(fs.readFileSync("./test/static/client.pem", "latin1")),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"],
    );

    // Node accepts a CryptoKey here and only emits a deprecation warning, so the signature
    // would look valid until the shim is removed and would never work off-Node.
    // https://github.com/node-saml/xml-crypto/issues/545
    const sig = signerFor(cryptoKey as unknown as crypto.KeyLike);

    expect(() => sig.computeSignature(xml)).to.throw(/RsaSha256 needs a key that node:crypto/);
  });

  it("signs an ArrayBuffer identically to the equivalent string", function () {
    const signatureAlgorithms = new SignedXml().SignatureAlgorithms;
    const algorithm = new signatureAlgorithms[RSA_SHA256]();
    const privateKey = fs.readFileSync("./test/static/client.pem");
    const signedInfo = "<SignedInfo></SignedInfo>";
    const bytes = Buffer.from(signedInfo, "utf8");

    expect(
      algorithm.getSignature(
        bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
        privateKey,
      ),
    ).to.equal(algorithm.getSignature(signedInfo, privateKey));
  });
});
