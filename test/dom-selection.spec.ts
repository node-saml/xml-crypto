import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import * as xpath from "xpath";
import { expect } from "chai";
import { SignedXml, findAncestorNs, type SignedXmlOptions } from "../src/index";
import * as utils from "../src/utils";
import { EnvelopedSignature } from "../src/enveloped-signature";

const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
const envelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const signatureXPath =
  "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";

function signer(options: SignedXmlOptions = {}) {
  return new SignedXml({
    ...options,
    privateKey: fs.readFileSync("./test/static/client.pem"),
    canonicalizationAlgorithm: exclusiveC14n,
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  });
}

function sign(xml: string, options: SignedXmlOptions = {}) {
  const sig = signer(options);
  sig.addReference({
    xpath: "//*[local-name(.)='item']",
    transforms: [exclusiveC14n],
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  });
  sig.computeSignature(xml);
  return sig.getSignedXml();
}

function verify(signedXml: string) {
  const verifier = new SignedXml({
    publicCert: fs.readFileSync("./test/static/client_public.pem"),
  });
  const doc = new xmldom.DOMParser().parseFromString(signedXml);
  verifier.loadSignature(verifier.findSignatures(doc)[0]);
  return verifier.checkSignature(signedXml);
}

describe("DOM selection matches the XPath it replaces", function () {
  const xml =
    "<!--prolog--><?pi data?><root xmlns:a='urn:a'><a:x><!--inner--><y>text</y></a:x>" +
    "<z><![CDATA[cdata]]><y/></z></root><!--epilog-->";

  it("findDescendants walks the descendant axis in document order", function () {
    const doc = new xmldom.DOMParser().parseFromString(xml);
    for (const node of [doc, doc.documentElement, doc.documentElement.firstChild as Node]) {
      expect(utils.findDescendants(node)).to.deep.equal(xpath.select(".//node()", node));
    }
  });

  it("findDescendants does not recurse on deeply nested input", function () {
    const depth = 20000;
    const doc = new xmldom.DOMParser().parseFromString(
      `${"<a>".repeat(depth)}${"</a>".repeat(depth)}`,
    );
    expect(utils.findDescendants(doc)).to.have.length(depth);
  });

  it("findSignatures searches the whole document from any node, including a detached one", function () {
    const signedXml = sign("<root><item/><nested><item/></nested></root>");
    const doc = new xmldom.DOMParser().parseFromString(signedXml);
    const sig = new SignedXml();
    for (const node of [doc, doc.documentElement, doc.createElement("detached")]) {
      const found = sig.findSignatures(node);
      expect(found).to.have.length(1);
      expect(found).to.deep.equal(xpath.select(signatureXPath, node));
    }
  });

  it("findSignatures goes by namespace, not by the ds prefix", function () {
    const doc = new xmldom.DOMParser().parseFromString(
      "<root xmlns:ds='urn:not-dsig'><ds:Signature/></root>",
    );
    expect(new SignedXml().findSignatures(doc)).to.be.empty;
  });

  it("enveloped-signature without a signature node removes only a direct child", function () {
    const xml = `<root><Signature xmlns='http://www.w3.org/2000/09/xmldsig#'/></root>`;
    const doc = new xmldom.DOMParser().parseFromString(xml);
    new EnvelopedSignature().process(doc, {});
    expect(doc.documentElement.childNodes).to.have.length(1);
    new EnvelopedSignature().process(doc.documentElement, {});
    expect(doc.documentElement.childNodes).to.have.length(0);
  });

  it("enveloped-signature leaves a node without children unchanged", function () {
    const text = new xmldom.DOMParser().parseFromString("<a/>").createTextNode("x");
    expect(new EnvelopedSignature().process(text, {})).to.equal(text);
  });

  it("getCertFromKeyInfo takes the first X509Certificate in any namespace", function () {
    const pem = fs.readFileSync("./test/static/client_public.pem", "latin1");
    const base64 = pem.replace(/-----[^-]+-----|\s/g, "");
    const doc = new xmldom.DOMParser().parseFromString(
      `<KeyInfo><other:X509Data xmlns:other='urn:other'><other:X509Certificate>${base64}</other:X509Certificate>` +
        "</other:X509Data><X509Certificate>not a certificate</X509Certificate></KeyInfo>",
    );
    const expected = xpath.select1(".//*[local-name(.)='X509Certificate']", doc) as Node;
    expect(SignedXml.getCertFromKeyInfo(doc)).to.equal(
      utils.toPem(expected.textContent as string, "CERTIFICATE"),
    );
  });

  it("loadSignature reads the first Algorithm attribute without a namespace", function () {
    const sig = new SignedXml();
    sig.loadSignature(
      "<Signature xmlns='http://www.w3.org/2000/09/xmldsig#' xmlns:o='urn:o'><SignedInfo>" +
        "<CanonicalizationMethod o:Algorithm='urn:namespaced'/>" +
        `<CanonicalizationMethod Algorithm='${exclusiveC14n}'/><SignatureMethod Algorithm='urn:method'/>` +
        "<Reference URI=''><DigestMethod Algorithm='http://www.w3.org/2001/04/xmlenc#sha256'/>" +
        "<DigestValue>AA==</DigestValue></Reference></SignedInfo></Signature>",
    );
    expect(sig.canonicalizationAlgorithm).to.equal(exclusiveC14n);
    expect(sig.signatureAlgorithm).to.equal("urn:method");
  });

  it("loadSignature matches the Algorithm attribute name case-insensitively, as xpath did", function () {
    const signature =
      "<Signature xmlns='http://www.w3.org/2000/09/xmldsig#'><SignedInfo>" +
      `<CanonicalizationMethod algorithm='${exclusiveC14n}'/><SignatureMethod ALGORITHM='urn:method'/>` +
      "<Reference URI=''><DigestMethod Algorithm='http://www.w3.org/2001/04/xmlenc#sha256'/>" +
      "<DigestValue>AA==</DigestValue></Reference></SignedInfo></Signature>";
    const expected = xpath.select1(
      ".//*[local-name(.)='SignatureMethod']/@Algorithm",
      new xmldom.DOMParser().parseFromString(signature),
    ) as Attr;
    const sig = new SignedXml();
    sig.loadSignature(signature);
    expect(sig.canonicalizationAlgorithm).to.equal(exclusiveC14n);
    expect(sig.signatureAlgorithm).to.equal(expected.value);
  });

  it("findAncestorNs gives an element the result of the XPath that selects it", function () {
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const subset = "//*[local-name(.)='y']";
    expect(findAncestorNs(doc, xpath.select1(subset, doc) as Element)).to.deep.equal(
      findAncestorNs(doc, subset),
    );
  });
});

describe("ID lookup on verification", function () {
  it("finds a reference by an Id attribute in a namespace", function () {
    expect(verify(sign("<root><item/></root>", { idMode: "wssecurity" }))).to.be.true;
  });

  it("rejects another element with the same Id in a namespace", function () {
    const signedXml = sign("<root xmlns:o='urn:o'><item/></root>");
    const wrapped = signedXml.replace("</root>", "<o:fake o:Id='_0'/></root>");
    expect(() => verify(wrapped)).to.throw(/multiple elements with the same value/);
  });

  it("rejects one element carrying the same value in Id and id", function () {
    const signedXml = sign("<root><item/></root>");
    const doubled = signedXml.replace('Id="_0"', 'Id="_0" id="_0"');
    expect(() => verify(doubled)).to.throw(/multiple elements with the same value/);
  });

  it("counts an xmlns:Id declaration with the same value, as xpath did", function () {
    const signedXml = sign("<root><item/></root>");
    const wrapped = signedXml.replace("</root>", "<fake xmlns:Id='_0'/></root>");
    expect(() => verify(wrapped)).to.throw(/multiple elements with the same value/);
  });

  it("does not count Id and a namespaced Id on one element twice", function () {
    const signedXml = sign("<root xmlns:o='urn:o'><item/></root>");
    const both = signedXml.replace('Id="_0"', 'Id="_0" o:Id="_0"');
    expect(() => verify(both)).not.to.throw();
  });
});

describe("Selecting without XPath when signing", function () {
  const digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

  it("signs the elements a select function returns", function () {
    const sig = signer();
    sig.addReference({
      select: (doc) => Array.from(doc.getElementsByTagName("item")),
      transforms: [envelopedSignature, exclusiveC14n],
      digestAlgorithm,
    });
    sig.computeSignature("<root><item>a</item><item>b</item></root>");
    expect(sig.getSignedXml().match(/<Reference /g)).to.have.length(2);
    expect(verify(sig.getSignedXml())).to.be.true;
  });

  it("places the signature relative to the node a location.reference function returns", function () {
    const sig = signer();
    sig.addReference({
      select: (doc) => [doc.documentElement],
      transforms: [envelopedSignature, exclusiveC14n],
      digestAlgorithm,
    });
    sig.computeSignature("<root><header/><body/></root>", {
      location: { reference: (doc) => doc.getElementsByTagName("header")[0], action: "after" },
    });
    expect(sig.getSignedXml()).to.match(/<header\/><Signature /);
    expect(verify(sig.getSignedXml())).to.be.true;
  });

  it("signs asynchronously with select and a location.reference function", async function () {
    const sig = signer();
    sig.addReference({
      select: (doc) => [doc.documentElement],
      transforms: [envelopedSignature, exclusiveC14n],
      digestAlgorithm,
    });
    await sig.computeSignatureAsync("<root><header/></root>", {
      location: { reference: (doc) => doc.getElementsByTagName("header")[0], action: "append" },
    });
    expect(sig.getSignedXml()).to.match(/<header><Signature /);
    expect(verify(sig.getSignedXml())).to.be.true;
  });

  it("signs the whole document with select and isEmptyUri", function () {
    const sig = signer();
    sig.addReference({
      select: (doc) => [doc.documentElement],
      transforms: [envelopedSignature, exclusiveC14n],
      digestAlgorithm,
      isEmptyUri: true,
    });
    sig.computeSignature("<root><item/></root>");
    expect(sig.getSignedXml()).to.include('<Reference URI="">');
    expect(sig.getSignedXml()).not.to.include("Id=");
    expect(verify(sig.getSignedXml())).to.be.true;
  });

  it("signs an Object in the signature when select finds nothing in the input", function () {
    const sig = signer({ objects: [{ content: "<value>object-data</value>" }] });
    sig.addReference({
      select: (doc) => Array.from(doc.getElementsByTagNameNS("*", "Object")),
      transforms: [exclusiveC14n],
      digestAlgorithm,
    });
    sig.computeSignature("<root/>");
    const signedXml = sig.getSignedXml();
    expect(signedXml).to.match(/<Object Id="_0">/);
    expect(verify(signedXml)).to.be.true;
    expect(verify(signedXml.replace("object-data", "tampered"))).to.be.false;
  });

  it("rejects a reference with both xpath and select", function () {
    expect(() =>
      signer().addReference({
        xpath: "/*",
        select: (doc) => [doc.documentElement],
        transforms: [exclusiveC14n],
        digestAlgorithm,
      }),
    ).to.throw("a reference takes either xpath or select, not both");
  });

  it("rejects a select function that finds nothing", function () {
    const sig = signer();
    sig.addReference({ select: () => [], transforms: [exclusiveC14n], digestAlgorithm });
    expect(() => sig.computeSignature("<root/>")).to.throw(
      "the reference's select function found nothing to sign",
    );
  });

  it("rejects a location.reference function that returns no node", function () {
    const sig = signer();
    sig.addReference({ xpath: "/*", transforms: [exclusiveC14n], digestAlgorithm });
    expect(() => sig.computeSignature("<root/>", { location: { reference: () => null } })).to.throw(
      "the location.reference function did not return a node",
    );
  });
});
