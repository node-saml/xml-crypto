import { expect } from "chai";
import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import { SignedXml } from "../src/index";

describe("Signing compatibility", function () {
  const privateKey = fs.readFileSync("./test/static/client.pem");
  const publicCert = fs.readFileSync("./test/static/client_public.pem");
  const canonicalization = "http://www.w3.org/2001/10/xml-exc-c14n#";
  const enveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

  for (const useCallback of [false, true]) {
    describe(useCallback ? "with a callback" : "without a callback", function () {
      for (const { name, reference, detached } of [
        { name: "signs all input elements", reference: "//*", detached: false },
        {
          name: "signs an element selected by the absence of an ID",
          reference: "/root[not(@Id)]",
          detached: false,
        },
        { name: "creates a verifiable detached signature", reference: "/*", detached: true },
      ]) {
        it(name, async function () {
          const signer = new SignedXml({
            privateKey,
            canonicalizationAlgorithm: canonicalization,
            signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
          });
          signer.addReference({
            xpath: reference,
            transforms: detached ? [canonicalization] : [enveloped, canonicalization],
            digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
          });

          const xml = "<root>trusted</root>";
          if (useCallback) {
            await new Promise<void>((resolve, reject) => {
              signer.computeSignature(xml, (err) => (err ? reject(err) : resolve()));
            });
          } else {
            signer.computeSignature(xml);
          }

          const signedXml = detached
            ? // eslint-disable-next-line deprecation/deprecation
              signer.getOriginalXmlWithIds()
            : signer.getSignedXml();
          const verifier = new SignedXml({ publicCert });
          verifier.loadSignature(signer.getSignatureXml());

          expect(verifier.checkSignature(signedXml)).to.be.true;
          expect(verifier.getSignedReferences()).to.deep.equal(['<root Id="_0">trusted</root>']);
          expect(verifier.checkSignature(signedXml.replace("trusted", "tampered"))).to.be.false;
          expect(verifier.getSignedReferences()).to.be.empty;
        });
      }
    });
  }

  for (const objectFirst of [false, true]) {
    it(`preserves input targets alongside an Object reference placed ${objectFirst ? "first" : "last"}`, function () {
      const signer = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: canonicalization,
        signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        objects: [{ content: "<value>object-data</value>" }],
      });
      const inputReference = {
        xpath: "//*",
        transforms: [enveloped, canonicalization],
        digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      };
      const objectReference = {
        xpath: "//*[local-name(.)='Object']",
        transforms: [canonicalization],
        digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      };
      for (const reference of objectFirst
        ? [objectReference, inputReference]
        : [inputReference, objectReference]) {
        signer.addReference(reference);
      }

      signer.computeSignature("<root><value>trusted</value></root>");

      const signedXml = signer.getSignedXml();
      const verifier = new SignedXml({ publicCert });
      verifier.loadSignature(signer.getSignatureXml());
      expect(verifier.checkSignature(signedXml)).to.be.true;
      const signedElements = verifier
        .getSignedReferences()
        .map((xml) => new xmldom.DOMParser().parseFromString(xml).documentElement.localName);
      expect(signedElements).to.deep.equal(
        objectFirst ? ["Object", "root", "value"] : ["root", "value", "Object"],
      );
      for (const content of ["trusted", "object-data"]) {
        expect(verifier.checkSignature(signedXml.replace(content, "tampered"))).to.be.false;
        expect(verifier.getSignedReferences()).to.be.empty;
      }
    });
  }

  it("retains ancestor namespaces when adding an ID changes the reference XPath's result", function () {
    const signer = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: canonicalization,
      signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    });
    signer.addReference({
      xpath: "/root/item[not(@Id)]",
      transforms: ["http://www.w3.org/TR/2001/REC-xml-c14n-20010315"],
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    });

    signer.computeSignature('<root xmlns:unused="urn:unused"><item>trusted</item></root>');

    const verifier = new SignedXml({ publicCert });
    verifier.loadSignature(signer.getSignatureXml());
    expect(verifier.checkSignature(signer.getSignedXml())).to.be.true;
    expect(verifier.getSignedReferences()).to.deep.equal([
      '<item xmlns:unused="urn:unused" Id="_0">trusted</item>',
    ]);
  });

  it("preserves an existing signature when reusing the signer to sign its output", function () {
    const signer = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: canonicalization,
      signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    });
    signer.addReference({
      xpath: "/*",
      transforms: [enveloped, canonicalization],
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    });
    signer.computeSignature("<root>trusted</root>");
    const originalSignature = signer.getSignatureXml();

    signer.computeSignature(signer.getSignedXml());

    const verifier = new SignedXml({ publicCert });
    verifier.loadSignature(signer.getSignatureXml());
    expect(verifier.checkSignature(signer.getSignedXml())).to.be.true;
    expect(
      verifier.checkSignature(
        signer
          .getSignedXml()
          .replace(
            originalSignature,
            originalSignature.replace("SignatureValue>", "SignatureValue>tampered"),
          ),
      ),
    ).to.be.false;
    expect(verifier.getSignedReferences()).to.be.empty;
  });
});
