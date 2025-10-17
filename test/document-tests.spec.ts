import { SignedXml } from "../src/index";
import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as fs from "fs";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";

describe("Document tests", function () {
  it("test with a document (using FileKeyInfo)", function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const node = xpath.select1(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );

    isDomNode.assertIsNodeLike(node);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.loadSignature(node);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("test with a document (using StringKeyInfo)", function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const node = xpath.select1(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );

    isDomNode.assertIsNodeLike(node);
    const sig = new SignedXml();
    const feidePublicCert = fs.readFileSync("./test/static/feide_public.pem");
    sig.publicCert = feidePublicCert;
    sig.loadSignature(node);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("test checkSignature auto-loads signature when not explicitly loaded", function () {
    const xml = fs.readFileSync("./test/static/invalid_signature - changed content.xml", "utf-8");
    const sig = new SignedXml();
    // Not calling loadSignature() - should auto-load
    // This should load the signature automatically even though validation will fail
    const result = sig.checkSignature(xml);

    expect(result).to.be.false;
    // The signature was loaded and processed, even though it's invalid
    expect(sig.getSignedReferences().length).to.equal(0);
  });

  it("test checkSignature throws error when no signature found", function () {
    const xml = "<root><data>test</data></root>";
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem");

    expect(() => sig.checkSignature(xml)).to.throw("No signature found in the document");
  });

  it("test checkSignature with callback handles no signature error", function (done) {
    const xml = "<root><data>test</data></root>";
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem");

    sig.checkSignature(xml, (error, isValid) => {
      expect(error).to.exist;
      expect(error?.message).to.equal("No signature found in the document");
      expect(isValid).to.be.false;
      done();
    });
  });

  it("test checkSignature with callback handles invalid signature", function (done) {
    // Load a document with an invalid signature (changed content)
    const xml = fs.readFileSync("./test/static/invalid_signature - changed content.xml", "utf-8");
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/feide_public.pem");

    sig.checkSignature(xml, (error, isValid) => {
      // When signature is cryptographically invalid (references don't validate),
      // the callback receives an error and isValid should be false.
      expect(error).to.exist;
      expect(error?.message).to.include("Could not validate all references");
      expect(isValid).to.be.false;
      expect(sig.getSignedReferences().length).to.equal(0);
      done();
    });
  });

  it("test checkSignature with callback handles invalid signature value", function (done) {
    // Load a document with an invalid signature value (tampered SignatureValue)
    const xml = fs.readFileSync("./test/static/invalid_signature - signature value.xml", "utf-8");
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");

    sig.checkSignature(xml, (error, isValid) => {
      // When the signature value itself is incorrect (Stage B verification fails),
      // the callback should receive both error and isValid === false for consistency
      expect(error).to.exist;
      expect(error?.message).to.include("invalid signature");
      expect(error?.message).to.include("is incorrect");
      expect(isValid).to.be.false;
      expect(sig.getSignedReferences().length).to.equal(0);
      done();
    });
  });

  it("should not reuse stale signature from previous checkSignature call", function () {
    const validXml = fs.readFileSync("./test/static/valid_signature.xml", "utf-8");
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");

    // First call with a valid signed document - should pass
    const firstResult = sig.checkSignature(validXml);
    expect(firstResult).to.be.true;

    // Second call with an unsigned document (no signature element at all)
    // Should throw an error about no signature found, not return true with the stale signature
    const unsignedXml = "<root><data>test content</data></root>";

    // This should throw an error about no signature found, not return true
    expect(() => sig.checkSignature(unsignedXml)).to.throw("No signature found in the document");
  });

  it("should not reuse stale signature from previous checkSignatureAsync call", async function () {
    const validXml = fs.readFileSync("./test/static/valid_signature.xml", "utf-8");
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");

    // First call with a valid signed document - should pass
    const firstResult = await sig.checkSignatureAsync(validXml);
    expect(firstResult).to.be.true;

    // Second call with an unsigned document (no signature element at all)
    // Should throw an error about no signature found, not return true with the stale signature
    const unsignedXml = "<root><data>test content</data></root>";

    // This should throw an error about no signature found, not return true
    try {
      await sig.checkSignatureAsync(unsignedXml);
      expect.fail("Should have thrown an error");
    } catch (error) {
      expect(error).to.exist;
      expect((error as Error).message).to.equal("No signature found in the document");
    }
  });

  it("should not reuse manually loaded signature from different document", function () {
    const validXml1 = fs.readFileSync("./test/static/valid_signature.xml", "utf-8");
    const validXml2 = fs.readFileSync("./test/static/valid_signature_utf8.xml", "utf-8");

    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");

    // Manually load signature from first document
    const doc1 = new xmldom.DOMParser().parseFromString(validXml1);
    const signature1 = sig.findSignatures(doc1)[0];
    sig.loadSignature(signature1);

    // First call should pass
    const firstResult = sig.checkSignature(validXml1);
    expect(firstResult).to.be.true;

    // Second call with a DIFFERENT document should NOT reuse the signature from doc1
    // It should auto-reload and use the signature from doc2
    const secondResult = sig.checkSignature(validXml2);
    expect(secondResult).to.be.true; // Should still validate correctly with doc2's signature
  });

  it("should not reuse manually loaded signature from different document (async)", async function () {
    const validXml1 = fs.readFileSync("./test/static/valid_signature.xml", "utf-8");
    const validXml2 = fs.readFileSync("./test/static/valid_signature_utf8.xml", "utf-8");

    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");

    // Manually load signature from first document
    const doc1 = new xmldom.DOMParser().parseFromString(validXml1);
    const signature1 = sig.findSignatures(doc1)[0];
    sig.loadSignature(signature1);

    // First call should pass
    const firstResult = await sig.checkSignatureAsync(validXml1);
    expect(firstResult).to.be.true;

    // Second call with a DIFFERENT document should NOT reuse the signature from doc1
    // It should auto-reload and use the signature from doc2
    const secondResult = await sig.checkSignatureAsync(validXml2);
    expect(secondResult).to.be.true; // Should still validate correctly with doc2's signature
  });

  it("should prevent stale signature attack with manually loaded signature", function () {
    const validXml = fs.readFileSync("./test/static/valid_signature.xml", "utf-8");

    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");

    // Manually load signature from the valid document
    const doc = new xmldom.DOMParser().parseFromString(validXml);
    const signatureNode = sig.findSignatures(doc)[0];
    sig.loadSignature(signatureNode);

    // First call should pass
    const firstResult = sig.checkSignature(validXml);
    expect(firstResult).to.be.true;

    // Try to validate an unsigned document - should fail
    // Even though we manually loaded a signature, it shouldn't be reused for a different document
    const unsignedXml = "<root><data>test content</data></root>";

    expect(() => sig.checkSignature(unsignedXml)).to.throw("No signature found in the document");
  });

  it("should prevent stale signature attack with manually loaded signature (async)", async function () {
    const validXml = fs.readFileSync("./test/static/valid_signature.xml", "utf-8");

    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");

    // Manually load signature from the valid document
    const doc = new xmldom.DOMParser().parseFromString(validXml);
    const signatureNode = sig.findSignatures(doc)[0];
    sig.loadSignature(signatureNode);

    // First call should pass
    const firstResult = await sig.checkSignatureAsync(validXml);
    expect(firstResult).to.be.true;

    // Try to validate an unsigned document - should fail
    // Even though we manually loaded a signature, it shouldn't be reused for a different document
    const unsignedXml = "<root><data>test content</data></root>";

    try {
      await sig.checkSignatureAsync(unsignedXml);
      expect.fail("Should have thrown an error");
    } catch (error) {
      expect(error).to.exist;
      expect((error as Error).message).to.equal("No signature found in the document");
    }
  });

  it("should reject unsigned document after preloading signature (vulnerability test)", function () {
    // This test validates the fix for the vulnerability where:
    // loadSignature() followed by checkSignature(unsignedXml) would incorrectly validate
    // because shouldReloadSignature would be false (signedXml is undefined)

    const validXml = fs.readFileSync("./test/static/valid_signature.xml", "utf-8");
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");

    // Load a valid signature from somewhere
    const doc = new xmldom.DOMParser().parseFromString(validXml);
    const signatureNode = sig.findSignatures(doc)[0];
    sig.loadSignature(signatureNode);

    // Now try to validate an UNSIGNED document
    // Before the fix: this would pass validation using the preloaded signature!
    // After the fix: this should reject because the unsigned document has no signature
    const unsignedXml = "<root><data>unsigned malicious content</data></root>";

    expect(() => sig.checkSignature(unsignedXml)).to.throw("No signature found in the document");
  });

  it("should reject unsigned document after preloading signature (async vulnerability test)", async function () {
    // This test validates the fix for the vulnerability where:
    // loadSignature() followed by checkSignatureAsync(unsignedXml) would incorrectly validate
    // because shouldReloadSignature would be false (signedXml is undefined)

    const validXml = fs.readFileSync("./test/static/valid_signature.xml", "utf-8");
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");

    // Load a valid signature from somewhere
    const doc = new xmldom.DOMParser().parseFromString(validXml);
    const signatureNode = sig.findSignatures(doc)[0];
    sig.loadSignature(signatureNode);

    // Now try to validate an UNSIGNED document
    // Before the fix: this would pass validation using the preloaded signature!
    // After the fix: this should reject because the unsigned document has no signature
    const unsignedXml = "<root><data>unsigned malicious content</data></root>";

    try {
      await sig.checkSignatureAsync(unsignedXml);
      expect.fail("Should have thrown 'No signature found in the document'");
    } catch (error) {
      expect(error).to.exist;
      expect((error as Error).message).to.equal("No signature found in the document");
    }
  });

  it("should allow detached signature scenario (first validation)", function () {
    // This test ensures we still support legitimate detached signature use cases
    // where the signature is stored separately from the content

    const xml = "<library>" + "<book>" + "<name>Harry Potter</name>" + "</book>" + "</library>";

    const signature =
      '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' +
      "<SignedInfo>" +
      '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
      '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>' +
      '<Reference URI="">' +
      "<Transforms>" +
      '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
      "</Transforms>" +
      '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
      "<DigestValue>1tjZsV007JgvE1YFe1C8sMQ+iEg=</DigestValue>" +
      "</Reference>" +
      "</SignedInfo>" +
      "<SignatureValue>FONRc5/nnQE2GMuEV0wK5/ofUJMHH7dzZ6VVd+oHDLfjfWax/lCMzUahJxW1i/dtm9Pl0t2FbJONVd3wwDSZzy6u5uCnj++iWYkRpIEN19RAzEMD1ejfZET8j3db9NeBq2JjrPbw81Fm7qKvte6jGa9ThTTB+1MHFRkC8qjukRM=</SignatureValue>" +
      "</Signature>";

    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");
    sig.loadSignature(signature);

    // This should work: detached signature on first validation
    const result = sig.checkSignature(xml);
    expect(result).to.be.true;
  });

  it("should prevent signature reuse on second validation with different content", function () {
    // This test validates that even with a preloaded detached signature,
    // we can't reuse it for a second validation with different content

    const xml1 = "<library>" + "<book>" + "<name>Harry Potter</name>" + "</book>" + "</library>";
    const xml2 =
      "<library>" + "<book>" + "<name>Malicious Content</name>" + "</book>" + "</library>";

    const signature =
      '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' +
      "<SignedInfo>" +
      '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
      '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>' +
      '<Reference URI="">' +
      "<Transforms>" +
      '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
      "</Transforms>" +
      '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
      "<DigestValue>1tjZsV007JgvE1YFe1C8sMQ+iEg=</DigestValue>" +
      "</Reference>" +
      "</SignedInfo>" +
      "<SignatureValue>FONRc5/nnQE2GMuEV0wK5/ofUJMHH7dzZ6VVd+oHDLfjfWax/lCMzUahJxW1i/dtm9Pl0t2FbJONVd3wwDSZzy6u5uCnj++iWYkRpIEN19RAzEMD1ejfZET8j3db9NeBq2JjrPbw81Fm7qKvte6jGa9ThTTB+1MHFRkC8qjukRM=</SignatureValue>" +
      "</Signature>";

    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");
    sig.loadSignature(signature);

    // First validation should work
    const result1 = sig.checkSignature(xml1);
    expect(result1).to.be.true;

    // Second validation with different content should fail
    // because the signature doesn't match the new content
    // and we can't find a signature in the new document
    expect(() => sig.checkSignature(xml2)).to.throw("No signature found in the document");
  });
});

describe("Validated node references tests", function () {
  it("should return references if the document is validly signed", function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const sig = new SignedXml();
    sig.getCertFromKeyInfo = SignedXml.getCertFromKeyInfo;
    sig.loadSignature(sig.findSignatures(doc)[0]);
    const validSignature = sig.checkSignature(xml);
    expect(validSignature).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);

    /* eslint-disable-next-line deprecation/deprecation */
    const ref = sig.getReferences()[0];
    const result = ref.getValidatedNode();
    expect(result?.toString()).to.equal(doc.toString());
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("should not return references if the document is not validly signed", function () {
    const xml = fs.readFileSync("./test/static/invalid_signature - changed content.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const sig = new SignedXml();
    sig.loadSignature(sig.findSignatures(doc)[0]);
    const validSignature = sig.checkSignature(xml);
    expect(validSignature).to.be.false;
    expect(sig.getSignedReferences().length).to.equal(0);

    /* eslint-disable-next-line deprecation/deprecation */
    const ref = sig.getReferences()[1];
    const result = ref.getValidatedNode();
    expect(result).to.be.null;
    expect(sig.getSignedReferences().length).to.equal(0);
  });

  it("should return `null` if the selected node isn't found", function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const sig = new SignedXml();
    sig.getCertFromKeyInfo = SignedXml.getCertFromKeyInfo;
    sig.loadSignature(sig.findSignatures(doc)[0]);
    const validSignature = sig.checkSignature(xml);
    expect(validSignature).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);

    /* eslint-disable-next-line deprecation/deprecation */
    const ref = sig.getReferences()[0];
    const result = ref.getValidatedNode("/non-existent-node");
    expect(result).to.be.null;
  });

  it("should return the selected node if it is validly signed", function () {
    const xml = fs.readFileSync("./test/static/valid_saml.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const sig = new SignedXml();
    sig.getCertFromKeyInfo = SignedXml.getCertFromKeyInfo;
    sig.loadSignature(sig.findSignatures(doc)[0]);
    const validSignature = sig.checkSignature(xml);
    expect(validSignature).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);

    /* eslint-disable-next-line deprecation/deprecation */
    const ref = sig.getReferences()[0];
    const result = ref.getValidatedNode(
      "//*[local-name()='Attribute' and @Name='mail']/*[local-name()='AttributeValue']/text()",
    );
    expect(result?.nodeValue).to.equal("henri.bergius@nemein.com");
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("should return `null` if the selected node isn't validly signed", function () {
    const xml = fs.readFileSync("./test/static/invalid_signature - changed content.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const sig = new SignedXml();
    sig.loadSignature(sig.findSignatures(doc)[0]);
    const validSignature = sig.checkSignature(xml);
    expect(validSignature).to.be.false;
    expect(sig.getSignedReferences().length).to.equal(0);

    /* eslint-disable-next-line deprecation/deprecation */
    const ref = sig.getReferences()[0];
    const result = ref.getValidatedNode(
      "//*[local-name()='Attribute' and @Name='mail']/*[local-name()='AttributeValue']/text()",
    );
    expect(result).to.be.null;
    // Not all references verified, so no references should be in `.getSignedReferences()`.
    expect(sig.getSignedReferences().length).to.equal(0);
  });
});
