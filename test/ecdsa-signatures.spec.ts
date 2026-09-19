import * as crypto from "crypto";
import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import * as xpath from "xpath";
import * as isDomNode from "@xmldom/is-dom-node";
import { expect } from "chai";
import { SignedXml } from "../src/index";

const signatureNamespace = "http://www.w3.org/2000/09/xmldsig#";
const canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
const digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";
const payload = '<payload Id="payload">attacker-controlled</payload>';

function createSignedXml(signatureAlgorithm: string, sign: (signedInfo: string) => string): string {
  const digestValue = crypto.createHash("sha256").update(payload).digest("base64");
  const signedInfo =
    `<SignedInfo xmlns="${signatureNamespace}">` +
    `<CanonicalizationMethod Algorithm="${canonicalizationAlgorithm}"></CanonicalizationMethod>` +
    `<SignatureMethod Algorithm="${signatureAlgorithm}"></SignatureMethod>` +
    '<Reference URI="#payload"><Transforms>' +
    `<Transform Algorithm="${canonicalizationAlgorithm}"></Transform></Transforms>` +
    `<DigestMethod Algorithm="${digestAlgorithm}"></DigestMethod>` +
    `<DigestValue>${digestValue}</DigestValue></Reference></SignedInfo>`;

  return (
    `<root>${payload}<Signature xmlns="${signatureNamespace}">${signedInfo}` +
    `<SignatureValue>${sign(signedInfo)}</SignatureValue></Signature></root>`
  );
}

function loadSignature(xml: string, publicCert: crypto.KeyLike): SignedXml {
  const doc = new xmldom.DOMParser().parseFromString(xml);
  const signature = xpath.select1(
    `//*[local-name(.)='Signature' and namespace-uri(.)='${signatureNamespace}']`,
    doc,
  );
  isDomNode.assertIsNodeLike(signature);
  const verifier = new SignedXml({ publicCert });
  verifier.loadSignature(signature);
  return verifier;
}

function signWith(signatureAlgorithm: string): string {
  const signer = new SignedXml({
    privateKey: fs.readFileSync("./test/static/client_ecdsa.pem"),
    signatureAlgorithm,
    canonicalizationAlgorithm,
  });
  signer.addReference({
    xpath: "//*[local-name(.)='x']",
    digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
    transforms: [canonicalizationAlgorithm],
  });
  signer.computeSignature('<root><x attr="value"></x></root>');
  return signer.getSignedXml();
}

describe("ECDSA signatures", function () {
  it("verifies the external ECDSA signature fixture", function () {
    const xml = fs.readFileSync("./test/static/valid_signature_ecdsa.xml", "utf8");
    const verifier = loadSignature(xml, fs.readFileSync("./test/static/ecdsa_external.pem"));

    expect(verifier.checkSignature(xml)).to.be.true;
    expect(verifier.getSignedReferences()).to.have.length(1);
  });

  for (const hash of ["sha256", "sha512"]) {
    const signatureAlgorithm = `http://www.w3.org/2001/04/xmldsig-more#ecdsa-${hash}`;

    describe(signatureAlgorithm, function () {
      it("verifies a document signed by the library", function () {
        const xml = signWith(signatureAlgorithm);
        const verifier = loadSignature(
          xml,
          fs.readFileSync("./test/static/client_public_ecdsa.pem"),
        );

        expect(verifier.checkSignature(xml)).to.be.true;
      });

      it("rejects a signed document after its referenced content is modified", function () {
        const xml = signWith(signatureAlgorithm);
        const doc = new xmldom.DOMParser().parseFromString(xml);
        const node = xpath.select1("//*[local-name(.)='x']", doc);
        isDomNode.assertIsElementNode(node);
        node.setAttribute("attr", "manipulatedValue");
        const manipulatedXml = new xmldom.XMLSerializer().serializeToString(doc);
        const verifier = loadSignature(
          manipulatedXml,
          fs.readFileSync("./test/static/client_public_ecdsa.pem"),
        );

        expect(verifier.checkSignature(manipulatedXml)).to.be.false;
      });

      it("does not expose signed references after rejecting a malformed signature", function () {
        const xml = createSignedXml(signatureAlgorithm, () => "AA==");
        const verifier = loadSignature(
          xml,
          fs.readFileSync("./test/static/client_public_ecdsa.pem"),
        );

        expect(() => verifier.checkSignature(xml)).to.throw();
        expect(verifier.getSignedReferences()).to.deep.equal([]);
      });

      // XMLDSig 1.1 §6.4.3: https://www.w3.org/TR/xmldsig-core1/#sec-ECDSA
      it("rejects an RSA private key instead of emitting an ECDSA-labeled RSA signature", function () {
        const signer = new SignedXml({
          privateKey: fs.readFileSync("./test/static/client.pem"),
          signatureAlgorithm,
          canonicalizationAlgorithm,
        });
        signer.addReference({
          xpath: "//*[@Id='payload']",
          digestAlgorithm,
          transforms: [canonicalizationAlgorithm],
        });

        expect(() => signer.computeSignature(`<root>${payload}</root>`)).to.throw();
      });

      it("rejects an RSA signature whose SignatureMethod declares ECDSA", function () {
        const privateKey = fs.readFileSync("./test/static/client.pem");
        const publicCert = fs.readFileSync("./test/static/client_public.pem");
        const sign = (signedInfo: string) =>
          crypto.sign(hash, Buffer.from(signedInfo), privateKey).toString("base64");
        const rsaXml = createSignedXml(`http://www.w3.org/2001/04/xmldsig-more#rsa-${hash}`, sign);
        expect(loadSignature(rsaXml, publicCert).checkSignature(rsaXml)).to.be.true;

        const xml = createSignedXml(signatureAlgorithm, sign);
        const verifier = loadSignature(xml, publicCert);

        expect(() => verifier.checkSignature(xml)).to.throw();
      });

      it("verifies an externally signed document using a public KeyObject", function () {
        const privateKey = fs.readFileSync("./test/static/client_ecdsa.pem");
        const publicCert = fs.readFileSync("./test/static/client_public_ecdsa.pem");
        const xml = createSignedXml(signatureAlgorithm, (signedInfo) =>
          crypto
            .sign(hash, Buffer.from(signedInfo), { key: privateKey, dsaEncoding: "ieee-p1363" })
            .toString("base64"),
        );
        expect(loadSignature(xml, publicCert).checkSignature(xml)).to.be.true;
        const verifier = loadSignature(xml, crypto.createPublicKey(publicCert));

        expect(verifier.checkSignature(xml)).to.be.true;
        expect(verifier.getSignedReferences()).to.deep.equal([payload]);
      });
    });
  }
});
