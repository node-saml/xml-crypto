import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import { SignedXml, type SignedXmlOptions } from "../src/index";
import * as fs from "fs";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";

describe("Signed references", function () {
  const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
  const rsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  const hmacSha1 = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
  const publicCert = fs.readFileSync("./test/static/client_public.pem");

  // Two references, so a check that fails on the second shows whether the first leaked.
  function sign(): string {
    const sig = new SignedXml({
      privateKey: fs.readFileSync("./test/static/client.pem"),
      canonicalizationAlgorithm: exclusiveC14n,
      signatureAlgorithm: rsaSha256,
    });
    for (const name of ["assertion", "extensions"]) {
      sig.addReference({
        xpath: `//*[local-name(.)='${name}']`,
        transforms: [exclusiveC14n],
        digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      });
    }
    sig.computeSignature("<response><assertion>signed</assertion><extensions/></response>");
    return sig.getSignedXml();
  }

  function loadSignature(sig: SignedXml, xml: string): SignedXml {
    const signature = xpath.select1(
      "//*[local-name(.)='Signature']",
      new xmldom.DOMParser().parseFromString(xml),
    );
    isDomNode.assertIsNodeLike(signature);
    sig.loadSignature(signature);
    return sig;
  }

  const cases: Array<[string, (xml: string) => string, SignedXmlOptions, string | RegExp]> = [
    [
      "the SignatureMethod is not enabled",
      (xml) => xml.replace(rsaSha256, hmacSha1),
      { publicCert },
      `signature algorithm '${hmacSha1}' is not supported`,
    ],
    [
      "there is no SignatureMethod",
      (xml) => xml.replace(/<SignatureMethod [^>]*\/>/, ""),
      { publicCert },
      "signatureAlgorithm is required",
    ],
    [
      "the second Reference names an unsupported DigestMethod",
      (xml) =>
        xml.replace(
          /(<Reference URI="#_1">.*?<DigestMethod Algorithm=")[^"]*/,
          "$1urn:example:unknown",
        ),
      { publicCert },
      "hash algorithm 'urn:example:unknown' is not supported",
    ],
    [
      "the id the second Reference points at is not unique",
      (xml) => xml.replace("</response>", '<extensions ID="_1"/></response>'),
      { publicCert },
      /in order to prevent signature wrapping attack/,
    ],
    ["no key is configured", (xml) => xml, {}, /^KeyInfo or publicCert or privateKey is required/],
    [
      "getCertFromKeyInfo cannot parse the embedded certificate",
      (xml) =>
        xml.replace(
          "</Signature>",
          "<KeyInfo><X509Data><X509Certificate>%%%</X509Certificate></X509Data></KeyInfo></Signature>",
        ),
      { getCertFromKeyInfo: SignedXml.getCertFromKeyInfo },
      "Unknown DER format.",
    ],
  ];

  for (const [problem, malform, options, error] of cases) {
    it(`are empty after checkSignature throws because ${problem}`, function () {
      const xml = malform(sign());
      const sig = loadSignature(new SignedXml(options), xml);

      expect(() => sig.checkSignature(xml)).to.throw(error);
      expect(sig.getSignedReferences()).to.be.empty;
      /* eslint-disable-next-line deprecation/deprecation */
      expect(sig.getReferences().map((ref) => ref.signedReference)).to.deep.equal([
        undefined,
        undefined,
      ]);
    });
  }

  it("from an earlier check do not survive a later check that throws", function () {
    const xml = sign();
    const sig = loadSignature(new SignedXml({ publicCert }), xml);
    expect(sig.checkSignature(xml)).to.be.true;
    expect(sig.getSignedReferences()).to.have.lengthOf(2);

    const unsupported = xml.replace(rsaSha256, hmacSha1);
    loadSignature(sig, unsupported);

    expect(() => sig.checkSignature(unsupported)).to.throw(/is not supported/);
    expect(sig.getSignedReferences()).to.be.empty;
  });
});
