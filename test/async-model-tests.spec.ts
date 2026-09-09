import * as crypto from "crypto";
import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import * as xpath from "xpath";
import * as isDomNode from "@xmldom/is-dom-node";
import { expect } from "chai";
import { SignedXml } from "../src/index";

const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

/** Only answers asynchronously, the way `crypto.subtle` or a signing server has to. */
class AsyncOnlySha256 {
  getAlgorithmName = () => SHA256;
  getHashAsync = async (xml: string) =>
    crypto.createHash("sha256").update(xml, "utf8").digest("base64");
}

class AsyncOnlyRsaSha256 {
  getAlgorithmName = () => RSA_SHA256;
  getSignatureAsync = async (signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike) =>
    crypto.createSign("RSA-SHA256").update(signedInfo).sign(privateKey, "base64");
  verifySignatureAsync = async (material: string, key: crypto.KeyLike, signatureValue: string) =>
    crypto.createVerify("RSA-SHA256").update(material).verify(key, signatureValue, "base64");
}

class NeitherFormSha256 {
  getAlgorithmName = () => SHA256;
}

class NeitherFormRsaSha256 {
  getAlgorithmName = () => RSA_SHA256;
}

const signatureAlgorithms = [
  "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
  RSA_SHA256,
  "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1",
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
];

function signer(signatureAlgorithm: string = RSA_SHA256): SignedXml {
  const sig = new SignedXml({ privateKey: fs.readFileSync("./test/static/client.pem") });
  sig.canonicalizationAlgorithm = EXC_C14N;
  sig.signatureAlgorithm = signatureAlgorithm;
  sig.addReference({
    xpath: "//*[local-name(.)='x']",
    digestAlgorithm: SHA256,
    transforms: [EXC_C14N],
  });
  return sig;
}

function signedInfoOf(signedXml: string): string {
  const doc = new xmldom.DOMParser().parseFromString(signedXml);
  const node = xpath.select1("//*[local-name(.)='SignedInfo']", doc);
  isDomNode.assertIsNodeLike(node);
  return node.toString();
}

function verifier(signedXml: string): SignedXml {
  const doc = new xmldom.DOMParser().parseFromString(signedXml);
  const node = xpath.select1(
    "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    doc,
  );
  isDomNode.assertIsNodeLike(node);
  const sig = new SignedXml({ publicCert: fs.readFileSync("./test/static/client_public.pem") });
  sig.canonicalizationAlgorithm = EXC_C14N;
  sig.loadSignature(node);
  return sig;
}

describe("Synchronous and asynchronous entry points", function () {
  const xml = '<root><x attr="value"></x></root>';

  signatureAlgorithms.forEach((signatureAlgorithm) => {
    it(`signs identically through either entry point with ${signatureAlgorithm}`, async function () {
      const sync = signer(signatureAlgorithm);
      sync.computeSignature(xml);

      const async = signer(signatureAlgorithm);
      await async.computeSignatureAsync(xml);

      // RSASSA-PSS salts every signature, so only the material being signed is comparable.
      expect(signedInfoOf(async.getSignedXml())).to.equal(signedInfoOf(sync.getSignedXml()));

      expect(verifier(sync.getSignedXml()).checkSignature(sync.getSignedXml())).to.be.true;
      expect(verifier(async.getSignedXml()).checkSignature(async.getSignedXml())).to.be.true;
    });
  });

  it("resolves with the instance, so getSignedXml() can be chained", async function () {
    const sig = signer();
    expect(await sig.computeSignatureAsync(xml)).to.equal(sig);
  });

  it("verifies a valid signature through either entry point", async function () {
    const sig = signer();
    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    expect(verifier(signedXml).checkSignature(signedXml)).to.be.true;
    expect(await verifier(signedXml).checkSignatureAsync(signedXml)).to.be.true;
  });

  it("reports a tampered document as invalid through either entry point", async function () {
    const sig = signer();
    sig.computeSignature(xml);
    const doc = new xmldom.DOMParser().parseFromString(sig.getSignedXml());
    const node = xpath.select1("//*[local-name(.)='x']", doc);
    isDomNode.assertIsElementNode(node);
    node.setAttribute("attr", "tampered");
    const tampered = new xmldom.XMLSerializer().serializeToString(doc);

    expect(verifier(tampered).checkSignature(tampered)).to.be.false;
    expect(await verifier(tampered).checkSignatureAsync(tampered)).to.be.false;
  });

  describe("an async-only algorithm", function () {
    it("signs through computeSignatureAsync and verifies against the synchronous path", async function () {
      const sig = signer();
      sig.HashAlgorithms[SHA256] = AsyncOnlySha256;
      sig.SignatureAlgorithms[RSA_SHA256] = AsyncOnlyRsaSha256;
      await sig.computeSignatureAsync(xml);
      const signedXml = sig.getSignedXml();

      expect(verifier(signedXml).checkSignature(signedXml)).to.be.true;
    });

    // Regressed in v6.1.0: `checkSignature` called `verifySignature` in its synchronous
    // three-argument form and never passed the callback down, so an async-only verifier
    // could not report a valid signature at all.
    // https://github.com/node-saml/xml-crypto/issues/546
    it("verifies through checkSignatureAsync", async function () {
      const sig = signer();
      sig.computeSignature(xml);
      const signedXml = sig.getSignedXml();

      const check = verifier(signedXml);
      check.HashAlgorithms[SHA256] = AsyncOnlySha256;
      check.SignatureAlgorithms[RSA_SHA256] = AsyncOnlyRsaSha256;

      expect(await check.checkSignatureAsync(signedXml)).to.be.true;
    });

    it("names the entry point to use when reached from computeSignature", function () {
      const sig = signer();
      sig.HashAlgorithms[SHA256] = AsyncOnlySha256;

      expect(() => sig.computeSignature(xml)).to.throw(
        "AsyncOnlySha256 is async-only; use computeSignatureAsync()",
      );
    });

    it("names the entry point to use when reached from checkSignature", function () {
      const sig = signer();
      sig.computeSignature(xml);
      const signedXml = sig.getSignedXml();

      const check = verifier(signedXml);
      check.SignatureAlgorithms[RSA_SHA256] = AsyncOnlyRsaSha256;

      expect(() => check.checkSignature(signedXml)).to.throw(
        "AsyncOnlyRsaSha256 is async-only; use checkSignatureAsync()",
      );
    });

    it("leaves no half-built Signature behind when signing fails", function () {
      const sig = signer();
      sig.HashAlgorithms[SHA256] = AsyncOnlySha256;

      expect(() => sig.computeSignature(xml)).to.throw();
      expect(() => sig.getSignatureXml()).to.not.throw();
      expect(sig.getSignatureXml()).to.equal("");
    });
  });

  it("says so when an algorithm implements neither form", async function () {
    const sig = signer();
    sig.HashAlgorithms[SHA256] = NeitherFormSha256;

    const message = "NeitherFormSha256 implements neither getHash() nor getHashAsync()";
    expect(() => sig.computeSignature(xml)).to.throw(message);

    const asyncSig = signer();
    asyncSig.HashAlgorithms[SHA256] = NeitherFormSha256;
    let rejection: Error | undefined;
    try {
      await asyncSig.computeSignatureAsync(xml);
    } catch (error) {
      rejection = error as Error;
    }
    expect(rejection?.message).to.equal(message);
  });

  describe("the removed callback form", function () {
    it("throws from computeSignature rather than never calling back", function () {
      expect(() => signer().computeSignature(xml, (() => undefined) as never)).to.throw(
        TypeError,
        "The callback form was removed in 7.0; use computeSignatureAsync()",
      );
      expect(() => signer().computeSignature(xml, {}, (() => undefined) as never)).to.throw(
        TypeError,
        "The callback form was removed in 7.0; use computeSignatureAsync()",
      );
    });

    it("throws from checkSignature rather than never calling back", function () {
      const sig = signer();
      sig.computeSignature(xml);
      const signedXml = sig.getSignedXml();

      expect(() =>
        verifier(signedXml).checkSignature(signedXml, (() => undefined) as never),
      ).to.throw(TypeError, "The callback form was removed in 7.0; use checkSignatureAsync()");
    });
  });

  it("rejects rather than throwing synchronously for a configuration error", async function () {
    const sig = signer();
    sig.signatureAlgorithm = undefined;

    let rejection: Error | undefined;
    const promise = sig.computeSignatureAsync(xml).catch((error: Error) => {
      rejection = error;
    });
    expect(rejection, "should not have thrown before the promise settled").to.be.undefined;
    await promise;
    expect(rejection?.message).to.equal("signatureAlgorithm is required");
  });

  describe("validateElementAgainstReferencesAsync", function () {
    async function loadedVerifier(): Promise<{ sig: SignedXml; doc: Document; signed: string }> {
      const sig = signer();
      sig.computeSignature(xml);
      const signed = sig.getSignedXml();

      const check = verifier(signed);
      expect(await check.checkSignatureAsync(signed)).to.be.true;

      return { sig: check, doc: new xmldom.DOMParser().parseFromString(signed), signed };
    }

    it("finds the reference whose digest matches the element", async function () {
      const { sig, doc } = await loadedVerifier();
      const element = xpath.select1("//*[local-name(.)='x']", doc);
      isDomNode.assertIsElementNode(element);

      const matched = await sig.validateElementAgainstReferencesAsync(element, doc);

      expect(matched.uri).to.equal("#_0");
    });

    it("uses an async-only digest algorithm", async function () {
      const { sig, doc } = await loadedVerifier();
      sig.HashAlgorithms[SHA256] = AsyncOnlySha256;
      const element = xpath.select1("//*[local-name(.)='x']", doc);
      isDomNode.assertIsElementNode(element);

      expect((await sig.validateElementAgainstReferencesAsync(element, doc)).uri).to.equal("#_0");
    });

    it("rejects when no reference matches the element", async function () {
      const { sig, doc } = await loadedVerifier();
      const unsigned = xpath.select1("//*[local-name(.)='Signature']", doc);
      isDomNode.assertIsElementNode(unsigned);

      let rejection: Error | undefined;
      try {
        await sig.validateElementAgainstReferencesAsync(unsigned, doc);
      } catch (error) {
        rejection = error as Error;
      }

      expect(rejection?.message).to.equal("No references passed validation");
    });
  });

  it("reports a reference it cannot resolve as invalid, asynchronously", async function () {
    const sig = signer();
    sig.computeSignature(xml);
    const signed = sig.getSignedXml();
    // Break the element the reference points at, leaving the reference itself intact.
    const tampered = signed.replace('Id="_0"', 'Id="_9"');

    expect(await verifier(tampered).checkSignatureAsync(tampered)).to.be.false;
  });

  it("names computeSignatureAsync when only the signature algorithm is async-only", function () {
    const sig = signer();
    sig.SignatureAlgorithms[RSA_SHA256] = AsyncOnlyRsaSha256;

    expect(() => sig.computeSignature(xml)).to.throw(
      "AsyncOnlyRsaSha256 is async-only; use computeSignatureAsync()",
    );
  });

  it("rejects when the signature algorithm implements neither form", async function () {
    const sig = signer();
    sig.SignatureAlgorithms[RSA_SHA256] = NeitherFormRsaSha256;

    let rejection: Error | undefined;
    try {
      await sig.computeSignatureAsync(xml);
    } catch (error) {
      rejection = error as Error;
    }

    expect(rejection?.message).to.equal(
      "NeitherFormRsaSha256 implements neither getSignature() nor getSignatureAsync()",
    );
  });

  it("rejects when the verification algorithm implements neither form", async function () {
    const sig = signer();
    sig.computeSignature(xml);
    const signed = sig.getSignedXml();

    const check = verifier(signed);
    check.SignatureAlgorithms[RSA_SHA256] = NeitherFormRsaSha256;

    let rejection: Error | undefined;
    try {
      await check.checkSignatureAsync(signed);
    } catch (error) {
      rejection = error as Error;
    }

    expect(rejection?.message).to.equal(
      "NeitherFormRsaSha256 implements neither verifySignature() nor verifySignatureAsync()",
    );
  });
});
