import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import { SignedXml } from "../src/index";
import * as fs from "fs";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";

const C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

function signBook(signatureAlgorithm: string = RSA_SHA1): string {
  const signer = new SignedXml({
    privateKey: fs.readFileSync("./test/static/client.pem"),
    canonicalizationAlgorithm: C14N,
    signatureAlgorithm,
  });
  signer.addReference({
    xpath: "//*[local-name(.)='book']",
    transforms: [ENVELOPED, C14N],
    digestAlgorithm: SHA1,
  });
  signer.computeSignature("<library><book Id='b1'><title>Harry Potter</title></book></library>");
  return signer.getSignedXml();
}

function wrapAlgorithm(xml: string, element: string, uri: string, wrapped: string): string {
  const needle = `<${element} Algorithm="${uri}"/>`;
  expect(xml.includes(needle), `signed xml should contain ${needle}`).to.equal(true);
  return xml.replace(needle, `<${element} Algorithm="${wrapped}"/>`);
}

function load(xml: string): SignedXml {
  const doc = new xmldom.DOMParser().parseFromString(xml, "text/xml");
  const signatureNode = xpath.select1("//*[local-name(.)='Signature']", doc);
  isDomNode.assertIsNodeLike(signatureNode);
  const sig = new SignedXml({
    publicCert: fs.readFileSync("./test/static/client_public.pem"),
  });
  sig.loadSignature(signatureNode);
  return sig;
}

function insertObjectBeforeSignedInfo(xml: string, objectInnerXml: string): string {
  const object = `<Object>${objectInnerXml}</Object>`;
  const withObject = xml.replace("<SignedInfo>", `${object}<SignedInfo>`);
  expect(withObject).to.not.equal(xml);
  return withObject;
}

function whitespaceDiagnostic(
  kind: "signature" | "canonicalization" | "hash",
  raw: string,
  supported: string,
): string {
  return (
    `${kind} algorithm ${JSON.stringify(raw)} is not supported; after collapsing ` +
    `XML whitespace it matches the supported algorithm ${JSON.stringify(supported)}. ` +
    `Algorithm attribute whitespace is not collapsed`
  );
}

describe("Algorithm URI whitespace diagnostics", function () {
  [
    {
      element: "CanonicalizationMethod",
      uri: C14N,
      kind: "canonicalization" as const,
      exercise: (xml: string, message: string) => {
        expect(() => load(xml)).to.throw(message);
      },
    },
    {
      element: "Transform",
      uri: C14N,
      kind: "canonicalization" as const,
      exercise: (xml: string, message: string) => {
        const sig = load(xml);
        expect(() => sig.checkSignature(xml)).to.throw(message);
      },
    },
    {
      element: "SignatureMethod",
      uri: RSA_SHA1,
      kind: "signature" as const,
      exercise: (xml: string, message: string) => {
        const sig = load(xml);
        expect(() => sig.checkSignature(xml)).to.throw(message);
      },
    },
    {
      element: "DigestMethod",
      uri: SHA1,
      kind: "hash" as const,
      exercise: (xml: string, message: string) => {
        const sig = load(xml);
        expect(() => sig.checkSignature(xml)).to.throw(message);
      },
    },
  ].forEach(({ element, uri, kind, exercise }) => {
    it(`rejects line-wrapped ${element} Algorithm with a whitespace diagnostic`, function () {
      // XML 1.0 attr normalization turns a pretty-printer line wrap into trailing spaces.
      const raw = `${uri}           `;
      exercise(wrapAlgorithm(signBook(), element, uri, raw), whitespaceDiagnostic(kind, raw, uri));
    });
  });

  it("still rejects a genuinely unregistered Algorithm URI", function () {
    const raw = "http://example.invalid/not-an-algorithm           ";
    const xml = wrapAlgorithm(signBook(), "SignatureMethod", RSA_SHA1, raw);
    const sig = load(xml);
    expect(() => sig.checkSignature(xml)).to.throw(
      `signature algorithm ${JSON.stringify(raw)} is not supported`,
    );
  });

  it("does not treat NBSP as Algorithm whitespace", function () {
    const raw = `\u00A0${C14N}`;
    const xml = wrapAlgorithm(signBook(), "CanonicalizationMethod", C14N, raw);
    expect(() => load(xml)).to.throw(
      `canonicalization algorithm ${JSON.stringify(raw)} is not supported`,
    );
  });
});

describe("SignatureMethod selection from unsigned content", function () {
  it("rejects a whitespace-padded SignatureMethod decoy outside SignedInfo", function () {
    const signed = signBook(RSA_SHA1);
    const raw = `  ${RSA_SHA1}  `;
    const decoy = insertObjectBeforeSignedInfo(signed, `<SignatureMethod Algorithm="${raw}"/>`);

    const doc = new xmldom.DOMParser().parseFromString(decoy, "text/xml");
    const signatureNode = xpath.select1("//*[local-name(.)='Signature']", doc);
    isDomNode.assertIsNodeLike(signatureNode);
    const selected = xpath.select1(
      ".//*[local-name(.)='SignatureMethod']/@Algorithm",
      signatureNode,
    );
    isDomNode.assertIsAttributeNode(selected);
    expect(selected.value).to.equal(raw);

    const sig = load(decoy);
    expect(sig.signatureAlgorithm).to.equal(raw);
    expect(() => sig.checkSignature(decoy)).to.throw(
      whitespaceDiagnostic("signature", raw, RSA_SHA1),
    );
  });

  it("documents that an exact SignatureMethod decoy outside SignedInfo is selected", function () {
    const signed = signBook(RSA_SHA1);
    const decoy = insertObjectBeforeSignedInfo(
      signed,
      `<SignatureMethod Algorithm="${RSA_SHA256}"/>`,
    );

    const sig = load(decoy);
    expect(sig.signatureAlgorithm).to.equal(RSA_SHA256);
    expect(() => sig.checkSignature(decoy)).to.throw(
      /invalid signature: the signature value .* is incorrect/,
    );
  });
});
