import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import { expect } from "chai";
import { SignedXml } from "../src/index";

const assertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion";
const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
const envelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

describe("processing instructions in a signed SAML assertion", function () {
  it("rejects a NameID whose textContent changes after signing", function () {
    const signer = new SignedXml({
      privateKey: fs.readFileSync("./test/static/client.pem"),
      canonicalizationAlgorithm: exclusiveC14n,
      signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    });
    signer.addReference({
      xpath: "//*[local-name(.)='Assertion']",
      transforms: [envelopedSignature, exclusiveC14n],
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    });
    signer.computeSignature(
      '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="assertion-1" Version="2.0" IssueInstant="2026-10-02T00:00:00Z"><saml:Issuer>https://idp.example</saml:Issuer><saml:Subject><saml:NameID>admin@victim.com.evil.com</saml:NameID></saml:Subject></saml:Assertion>',
      { location: { reference: "//*[local-name(.)='Issuer']", action: "after" } },
    );

    const signedXml = signer.getSignedXml();
    const tamperedXml = signedXml.replace(
      "admin@victim.com.evil.com",
      "admin@victim.com<?x .evil.com?>",
    );
    expect(tamperedXml).not.to.equal(signedXml);

    const tamperedDoc = new xmldom.DOMParser().parseFromString(tamperedXml);
    const nameId = tamperedDoc.getElementsByTagNameNS(assertionNamespace, "NameID")[0];
    expect(nameId.textContent).to.equal("admin@victim.com");

    const verify = (xml: string) => {
      const verifier = new SignedXml({
        publicCert: fs.readFileSync("./test/static/client_public.pem"),
      });
      const doc = new xmldom.DOMParser().parseFromString(xml);
      verifier.loadSignature(verifier.findSignatures(doc)[0]);
      return verifier.checkSignature(xml);
    };

    expect(verify(signedXml)).to.be.true;
    expect(verify(tamperedXml)).to.be.false;
  });
});
