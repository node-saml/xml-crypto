import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import { SignedXml, findAncestorNs } from "../src/index";
import * as fs from "fs";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";

const C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";

function signBook(): string {
  const signer = new SignedXml({
    privateKey: fs.readFileSync("./test/static/client.pem"),
    canonicalizationAlgorithm: C14N,
    signatureAlgorithm: RSA_SHA1,
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

function resignOverWrappedSignedInfo(xml: string): string {
  const doc = new xmldom.DOMParser().parseFromString(xml, "text/xml");
  const signatureNode = xpath.select1("//*[local-name(.)='Signature']", doc);
  isDomNode.assertIsNodeLike(signatureNode);
  const sig = new SignedXml();
  sig.loadSignature(signatureNode);
  if (typeof sig.canonicalizationAlgorithm !== "string") {
    throw new Error("canonicalizationAlgorithm missing after loadSignature");
  }
  if (sig.signatureAlgorithm == null) {
    throw new Error("signatureAlgorithm missing after loadSignature");
  }
  const AlgoCtor = sig.SignatureAlgorithms[sig.signatureAlgorithm];
  if (AlgoCtor == null) {
    throw new Error(`signature algorithm '${sig.signatureAlgorithm}' is not supported`);
  }
  const signedInfo = xpath.select1(".//*[local-name(.)='SignedInfo']", signatureNode);
  isDomNode.assertIsNodeLike(signedInfo);
  const canon = sig.getCanonXml([sig.canonicalizationAlgorithm], signedInfo, {
    ancestorNamespaces: findAncestorNs(doc, "//*[local-name(.)='SignedInfo']"),
  });
  const signatureValue = new AlgoCtor().getSignature(
    canon,
    fs.readFileSync("./test/static/client.pem"),
  );
  const resigned = xml.replace(
    /(<SignatureValue>)([^<]*)(<\/SignatureValue>)/,
    `$1${signatureValue}$3`,
  );
  if (resigned === xml) {
    throw new Error("failed to replace SignatureValue");
  }
  return resigned;
}

function expectWrappedSignatureVerifies(element: string, uri: string, wrapped: string) {
  const xml = resignOverWrappedSignedInfo(wrapAlgorithm(signBook(), element, uri, wrapped));
  expect(xml.includes(`Algorithm="${wrapped}"`)).to.equal(true);
  expect(load(xml).checkSignature(xml)).to.equal(true);
}

describe("xsd:anyURI whitespace collapse on Algorithm attributes", function () {
  it("resolves CanonicalizationMethod when Algorithm is line-wrapped", function () {
    const xml = wrapAlgorithm(signBook(), "CanonicalizationMethod", C14N, `${C14N}\n          `);
    const sig = load(xml);

    expect(sig.canonicalizationAlgorithm).to.equal(C14N);
    expect(sig.signatureAlgorithm).to.equal(RSA_SHA1);
    const ref = sig.getReferences()[0];
    expect(ref.digestAlgorithm).to.equal(SHA1);
    expect(ref.transforms).to.include(C14N);

    expect(() => sig.checkSignature(xml)).to.throw(/invalid signature/);
  });

  it("verifies CanonicalizationMethod when leading whitespace was signed over", function () {
    expectWrappedSignatureVerifies("CanonicalizationMethod", C14N, `\n          ${C14N}`);
  });

  [
    { element: "CanonicalizationMethod", uri: C14N },
    { element: "Transform", uri: C14N },
    { element: "SignatureMethod", uri: RSA_SHA1 },
    { element: "DigestMethod", uri: SHA1 },
  ].forEach(({ element, uri }) => {
    it(`verifies ${element} when line-wrapped Algorithm was signed over`, function () {
      expectWrappedSignatureVerifies(element, uri, `${uri}\n          `);
    });
  });

  it("misses the registry when Algorithm has an internal whitespace run", function () {
    const xml = wrapAlgorithm(
      signBook(),
      "CanonicalizationMethod",
      C14N,
      "http://www.w3.org/TR/2001/\t\n          REC-xml-c14n-20010315",
    );
    expect(() => load(xml)).to.throw(
      "canonicalization algorithm 'http://www.w3.org/TR/2001/ REC-xml-c14n-20010315' is not supported",
    );
  });

  it("does not treat NBSP as Algorithm whitespace", function () {
    const xml = wrapAlgorithm(signBook(), "CanonicalizationMethod", C14N, `\u00A0${C14N}`);
    expect(() => load(xml)).to.throw(`canonicalization algorithm '\u00A0${C14N}' is not supported`);
  });

  it("still rejects a genuinely unregistered Algorithm URI after whitespace collapse", function () {
    const xml = wrapAlgorithm(
      signBook(),
      "SignatureMethod",
      RSA_SHA1,
      "http://example.invalid/not-an-algorithm\n          ",
    );
    const sig = load(xml);
    expect(() => sig.checkSignature(xml)).to.throw(
      "signature algorithm 'http://example.invalid/not-an-algorithm' is not supported",
    );
  });
});
