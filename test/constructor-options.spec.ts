import * as fs from "fs";
import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";
import { SignedXml } from "../src/index";

const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
const rsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";

function signatureIn(xml: string): Node {
  const signature = xpath.select1(
    "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    new xmldom.DOMParser().parseFromString(xml),
  );
  isDomNode.assertIsNodeLike(signature);
  return signature;
}

describe("SignedXml constructor options", function () {
  it("uses idAttribute to reuse an existing ID when signing and find it when verifying", function () {
    const idAttribute = "AssertionID";
    const signer = new SignedXml({
      idAttribute,
      privateKey: fs.readFileSync("./test/static/client.pem"),
      canonicalizationAlgorithm: exclusiveC14n,
      signatureAlgorithm: rsaSha256,
    });
    signer.addReference({
      xpath: "//*[local-name(.)='item']",
      transforms: [exclusiveC14n],
      digestAlgorithm: sha256,
    });
    signer.computeSignature('<root><item AssertionID="item-1">trusted</item></root>');

    const signedXml = signer.getSignedXml();
    const doc = new xmldom.DOMParser().parseFromString(signedXml);
    const item = xpath.select1("//*[local-name(.)='item']", doc);
    const referenceUri = xpath.select1("string(//*[local-name(.)='Reference']/@URI)", doc);
    isDomNode.assertIsElementNode(item);

    expect(referenceUri).to.equal("#item-1");
    expect(item.getAttribute(idAttribute)).to.equal("item-1");
    expect(item.hasAttribute("Id")).to.be.false;

    const verifier = new SignedXml({
      idAttribute,
      publicCert: fs.readFileSync("./test/static/client_public.pem"),
    });
    verifier.loadSignature(signatureIn(signedXml));

    expect(verifier.checkSignature(signedXml)).to.be.true;
    expect(verifier.getSignedReferences()).to.deep.equal([
      '<item AssertionID="item-1">trusted</item>',
    ]);
  });

  it("applies implicitTransforms during verification", function () {
    const implicitTransform = "urn:xml-crypto:test:implicit-identity";
    let calls = 0;

    class ImplicitIdentity {
      process(node: Node) {
        calls += 1;
        return node;
      }

      getAlgorithmName() {
        return implicitTransform;
      }
    }

    const signer = new SignedXml({
      privateKey: fs.readFileSync("./test/static/client.pem"),
      canonicalizationAlgorithm: exclusiveC14n,
      signatureAlgorithm: rsaSha256,
    });
    signer.addReference({
      xpath: "//*[local-name(.)='item']",
      transforms: [exclusiveC14n],
      digestAlgorithm: sha256,
    });
    signer.computeSignature("<root><item>trusted</item></root>");
    const signedXml = signer.getSignedXml();

    const verifier = new SignedXml({
      implicitTransforms: [implicitTransform],
      publicCert: fs.readFileSync("./test/static/client_public.pem"),
    });
    verifier.CanonicalizationAlgorithms[implicitTransform] = ImplicitIdentity;
    verifier.loadSignature(signatureIn(signedXml));

    expect(verifier.checkSignature(signedXml)).to.be.true;
    expect(calls).to.equal(1);
    expect(verifier.getSignedReferences()).to.deep.equal(['<item Id="_0">trusted</item>']);
  });
});
