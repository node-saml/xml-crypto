import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import { expect } from "chai";
import { SignedXml } from "../src/index";

const canonicalizations = [
  ["inclusive", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"],
  ["exclusive", "http://www.w3.org/2001/10/xml-exc-c14n#"],
] as const;

const namespaceCases = [
  { name: "default", element: "item", declaration: "xmlns" },
  { name: "prefixed", element: "p:item", declaration: "xmlns:p" },
] as const;

describe("Namespace declarations in signed references", function () {
  for (const [algorithmName, canonicalizationAlgorithm] of canonicalizations) {
    for (const { name, element, declaration } of namespaceCases) {
      it(`rejects hidden Access in ${name} namespace under ${algorithmName} c14n`, function () {
        const signer = new SignedXml({
          privateKey: fs.readFileSync("./test/static/client.pem"),
          canonicalizationAlgorithm,
          signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        });
        signer.addReference({
          xpath: "//*[local-name(.)='item']",
          transforms: [canonicalizationAlgorithm],
          digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
        });
        signer.computeSignature(
          `<root><${element} ${declaration}="urn:test" Access="user">value</${element}></root>`,
        );

        const signedXml = signer.getSignedXml();
        const original = `${declaration}="urn:test" Access="user"`;
        expect(signedXml).to.include(original);
        const tampered = signedXml.replace(
          original,
          `${declaration}="urn:test&quot; Access=&quot;user"`,
        );
        const item = new xmldom.DOMParser()
          .parseFromString(tampered)
          .getElementsByTagName(element)[0];
        expect(item.hasAttribute("Access")).to.be.false;
        expect(item.namespaceURI).to.equal('urn:test" Access="user');

        const createVerifier = () => {
          const verifier = new SignedXml({
            publicCert: fs.readFileSync("./test/static/client_public.pem"),
          });
          verifier.loadSignature(signer.getSignatureXml());
          return verifier;
        };
        expect(createVerifier().checkSignature(signedXml)).to.be.true;
        const tamperedVerifier = createVerifier();
        expect(tamperedVerifier.checkSignature(tampered)).to.be.false;
        expect(tamperedVerifier.getSignedReferences()).to.be.empty;
      });
    }
  }
});
