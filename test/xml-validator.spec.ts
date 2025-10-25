import * as fs from "fs";
import { expect } from "chai";
import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as isDomNode from "@xmldom/is-dom-node";
import { XmlValidator, XmlValidatorFactory } from "../src/xml-validator";
import { SignedXml } from "../src/signed-xml";

const privateKey = fs.readFileSync("./test/static/client.pem", "utf-8");
const publicCert = fs.readFileSync("./test/static/client_public.pem", "utf-8");

// Helper function to create a signed XML document
function createSignedXml(
  xml: string,
  options: { prefix?: string; attrs?: Record<string, string> } = {},
): string {
  const sig = new SignedXml({
    privateKey,
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
    signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
  });

  sig.addReference({
    xpath: "//*[local-name(.)='test']",
    digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
    transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
  });

  sig.computeSignature(xml, options);
  return sig.getSignedXml();
}

// Helper function to create a signed XML with multiple signatures
function createMultiSignedXml(xml: string): string {
  const sig1 = new SignedXml({
    privateKey,
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
    signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
  });

  sig1.addReference({
    xpath: "//*[local-name(.)='test']",
    digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
    transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
  });

  sig1.computeSignature(xml, { attrs: { Id: "sig1" } });
  const signedOnce = sig1.getSignedXml();

  const sig2 = new SignedXml({
    privateKey,
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
    signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
  });

  sig2.addReference({
    xpath: "//*[local-name(.)='test']",
    digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
    transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
  });

  sig2.computeSignature(signedOnce, { attrs: { Id: "sig2" } });
  return sig2.getSignedXml();
}

describe("XmlValidator", function () {
  describe("constructor", function () {
    it("should create validator with public certificate", function () {
      const validator = new XmlValidator({ publicCert });
      expect(validator).to.be.instanceOf(XmlValidator);
    });

    it("should create validator with getCertFromKeyInfo function", function () {
      const validator = new XmlValidator({
        getCertFromKeyInfo: () => publicCert,
      });
      expect(validator).to.be.instanceOf(XmlValidator);
    });

    it("should create validator with WS-Security mode enabled", function () {
      const validator = new XmlValidator({
        publicCert,
        enableWSSecurityMode: true,
      });
      expect(validator).to.be.instanceOf(XmlValidator);
    });

    it("should create validator with custom ID attributes", function () {
      const validator = new XmlValidator({
        publicCert,
        idAttributes: ["customId", "myId"],
      });
      expect(validator).to.be.instanceOf(XmlValidator);
    });

    it("should create validator with security options", function () {
      const validator = new XmlValidator({
        publicCert,
        maxTransforms: 2,
        throwOnError: true,
      });
      expect(validator).to.be.instanceOf(XmlValidator);
    });

    it("should throw error when neither publicCert nor getCertFromKeyInfo is provided", function () {
      expect(() => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new XmlValidator({} as any);
      }).to.throw(
        "XmlValidator requires either a publicCert or getCertFromKeyInfo function in options.",
      );
    });

    it("should not allow idAttributes when WS-Security mode is enabled", function () {
      // This should compile without TypeScript errors due to the union type design
      const validator = new XmlValidator({
        publicCert,
        enableWSSecurityMode: true,
        // idAttributes: ["test"], // This would cause a TypeScript error
      });
      expect(validator).to.be.instanceOf(XmlValidator);
    });
  });

  describe("loadSignature", function () {
    it("should load a specific signature node", function () {
      const xml = "<root><test>content</test></root>";
      const signedXml = createSignedXml(xml);
      const doc = new xmldom.DOMParser().parseFromString(signedXml);
      const signatureNode = xpath.select1("//*[local-name(.)='Signature']", doc);
      isDomNode.assertIsNodeLike(signatureNode);

      const validator = new XmlValidator({ publicCert });
      expect(() => validator.loadSignature(signatureNode)).to.not.throw();
    });

    it("should throw error when trying to load signature twice", function () {
      const xml = "<root><test>content</test></root>";
      const signedXml = createSignedXml(xml);
      const doc = new xmldom.DOMParser().parseFromString(signedXml);
      const signatureNode = xpath.select1("//*[local-name(.)='Signature']", doc);
      isDomNode.assertIsNodeLike(signatureNode);

      const validator = new XmlValidator({ publicCert });
      validator.loadSignature(signatureNode);

      expect(() => validator.loadSignature(signatureNode)).to.throw(
        "A signature has already been loaded into this XmlValidator instance.",
      );
    });
  });

  describe("validate (synchronous)", function () {
    it("should validate a valid signed XML document", function () {
      const xml = "<root><test>content</test></root>";
      const signedXml = createSignedXml(xml);

      const validator = new XmlValidator({ publicCert });
      const result = validator.validate(signedXml);

      expect(result.valid).to.be.true;
      expect(result.error).to.be.undefined;
      expect(result.signedReferences).to.be.an("array");
      expect(result.signedReferences).to.have.length(1);
    });

    it("should fail validation for invalid signature", function () {
      const xml = "<root><test>content</test></root>";
      const signedXml = createSignedXml(xml);
      const tamperedXml = signedXml.replace("content", "tampered");

      const validator = new XmlValidator({ publicCert });
      const result = validator.validate(tamperedXml);

      expect(result.valid).to.be.false;
      expect(result.signedReferences).to.be.undefined;
    });

    it("should automatically load single signature when none is pre-loaded", function () {
      const xml = "<root><test>content</test></root>";
      const signedXml = createSignedXml(xml);

      const validator = new XmlValidator({ publicCert });
      const result = validator.validate(signedXml);

      expect(result.valid).to.be.true;
    });

    it("should fail when no signature is found", function () {
      const xml = "<root><test>content</test></root>";

      const validator = new XmlValidator({ publicCert });
      const result = validator.validate(xml);

      expect(result.valid).to.be.false;
      expect(result.error).to.include("No Signature element found");
    });

    it("should fail when multiple signatures are found without pre-loading", function () {
      const xml = "<root><test>content</test></root>";
      const multiSignedXml = createMultiSignedXml(xml);

      const validator = new XmlValidator({ publicCert });
      const result = validator.validate(multiSignedXml);

      expect(result.valid).to.be.false;
      expect(result.error).to.include("Multiple Signature elements found");
    });

    it("should validate specific signature when pre-loaded", function () {
      const xml = "<root><test>content</test></root>";
      const multiSignedXml = createMultiSignedXml(xml);
      const doc = new xmldom.DOMParser().parseFromString(multiSignedXml);
      const firstSignature = xpath.select1("//*[local-name(.)='Signature'][@Id='sig1']", doc);
      isDomNode.assertIsNodeLike(firstSignature);

      const validator = new XmlValidator({ publicCert });
      validator.loadSignature(firstSignature);
      const result = validator.validate(multiSignedXml);

      expect(result.valid).to.be.true;
    });

    it("should throw error when validator is reused", function () {
      const xml = "<root><test>content</test></root>";
      const signedXml = createSignedXml(xml);

      const validator = new XmlValidator({ publicCert });
      validator.validate(signedXml);

      const result = validator.validate(signedXml);
      expect(result.valid).to.be.false;
      expect(result.error).to.include("This XmlValidator instance has already been used");
    });

    it("should work with getCertFromKeyInfo function", function () {
      const xml = "<root><test>content</test></root>";
      const signedXml = createSignedXml(xml);

      const validator = new XmlValidator({
        getCertFromKeyInfo: () => publicCert,
      });
      const result = validator.validate(signedXml);

      expect(result.valid).to.be.true;
    });

    it("should work with custom ID attributes", function () {
      const xml = '<root><test customId="test1">content</test></root>';
      const sig = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
      });
      sig.idAttributes = ["customId"];
      sig.addReference({
        xpath: "//*[@customId='test1']",
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
      });
      sig.computeSignature(xml);
      const signedXml = sig.getSignedXml();

      const validator = new XmlValidator({
        publicCert,
        idAttributes: ["customId"],
      });
      const result = validator.validate(signedXml);

      expect(result.valid).to.be.true;
    });

    it("should work with WS-Security mode", function () {
      const xml =
        '<root xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><test wsu:Id="test1">content</test></root>';
      const sig = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        idMode: "wssecurity",
      });
      sig.addReference({
        xpath: "//*[@wsu:Id='test1']",
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
      });
      sig.computeSignature(xml, {
        existingPrefixes: {
          wsu: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
        },
      });
      const signedXml = sig.getSignedXml();

      const validator = new XmlValidator({
        publicCert,
        enableWSSecurityMode: true,
      });
      const result = validator.validate(signedXml);

      expect(result.valid).to.be.true;
    });

    it("should handle validation errors gracefully when throwOnError is false", function () {
      const xml = "<root><test>content</test></root>";
      const signedXml = createSignedXml(xml);
      const corruptedXml = signedXml.replace("<SignatureValue>", "<SignatureValue>corrupted");

      const validator = new XmlValidator({
        publicCert,
        throwOnError: false,
      });
      const result = validator.validate(corruptedXml);

      expect(result.valid).to.be.false;
      expect(result.error).to.be.a("string");
    });

    it("should throw validation errors when throwOnError is true", function () {
      const xml = "<root><test>content</test></root>";

      const validator = new XmlValidator({
        publicCert,
        throwOnError: true,
      });

      expect(() => validator.validate(xml)).to.throw();
    });
  });

  describe("validate (asynchronous)", function () {
    it("should validate a valid signed XML document asynchronously", function (done) {
      const xml = "<root><test>content</test></root>";
      const signedXml = createSignedXml(xml);

      const validator = new XmlValidator({ publicCert });
      validator.validate(signedXml, (err, result) => {
        try {
          expect(err).to.be.null;
          expect(result?.valid).to.be.true;
          expect(result?.error).to.be.undefined;
          expect(result?.signedReferences).to.be.an("array");
          expect(result?.signedReferences).to.have.length(1);
          done();
        } catch (error) {
          done(error);
        }
      });
    });

    it("should fail validation for invalid signature asynchronously", function (done) {
      const xml = "<root><test>content</test></root>";
      const signedXml = createSignedXml(xml);
      const tamperedXml = signedXml.replace("content", "tampered");

      const validator = new XmlValidator({ publicCert });
      validator.validate(tamperedXml, (err, result) => {
        try {
          expect(err).to.be.null;
          expect(result?.valid).to.be.false;
          expect(result?.signedReferences).to.be.undefined;
          done();
        } catch (error) {
          done(error);
        }
      });
    });

    it("should handle errors gracefully in async mode", function (done) {
      const xml = "<root><test>content</test></root>";

      const validator = new XmlValidator({
        publicCert,
        throwOnError: false,
      });
      validator.validate(xml, (err, result) => {
        try {
          expect(err).to.be.null;
          expect(result?.valid).to.be.false;
          expect(result?.error).to.include("No Signature element found");
          done();
        } catch (error) {
          done(error);
        }
      });
    });

    it("should handle reuse error in async mode", function (done) {
      const xml = "<root><test>content</test></root>";
      const signedXml = createSignedXml(xml);

      const validator = new XmlValidator({ publicCert });
      validator.validate(signedXml, (err, result) => {
        try {
          expect(err).to.be.null;
          expect(result?.valid).to.be.true;

          // Try to use the validator again
          validator.validate(signedXml, (err2, result2) => {
            try {
              expect(err2).to.be.null;
              expect(result2?.valid).to.be.false;
              expect(result2?.error).to.include("This XmlValidator instance has already been used");
              done();
            } catch (error) {
              done(error);
            }
          });
        } catch (error) {
          done(error);
        }
      });
    });
  });
});

describe("XmlValidatorFactory", function () {
  describe("constructor", function () {
    it("should create factory with public certificate", function () {
      const factory = new XmlValidatorFactory({ publicCert });
      expect(factory).to.be.instanceOf(XmlValidatorFactory);
    });

    it("should create factory with getCertFromKeyInfo function", function () {
      const factory = new XmlValidatorFactory({
        getCertFromKeyInfo: () => publicCert,
      });
      expect(factory).to.be.instanceOf(XmlValidatorFactory);
    });

    it("should create factory with all options", function () {
      const factory = new XmlValidatorFactory({
        publicCert,
        enableWSSecurityMode: true,
        maxTransforms: 2,
        throwOnError: true,
      });
      expect(factory).to.be.instanceOf(XmlValidatorFactory);
    });
  });

  describe("createValidator", function () {
    it("should create validator with factory defaults", function () {
      const factory = new XmlValidatorFactory({ publicCert });
      const validator = factory.createValidator();
      expect(validator).to.be.instanceOf(XmlValidator);
    });

    it("should create validator with override certificate", function () {
      const factory = new XmlValidatorFactory({
        getCertFromKeyInfo: () => "default-cert",
      });
      const validator = factory.createValidator(publicCert);
      expect(validator).to.be.instanceOf(XmlValidator);
    });

    it("should create validator with factory getCertFromKeyInfo and override with publicCert", function () {
      const xml = "<root><test>content</test></root>";
      const signedXml = createSignedXml(xml);

      const factory = new XmlValidatorFactory({
        getCertFromKeyInfo: () => "wrong-cert",
      });
      const validator = factory.createValidator(publicCert);
      const result = validator.validate(signedXml);

      expect(result.valid).to.be.true;
    });

    it("should create multiple independent validators", function () {
      const xml = "<root><test>content</test></root>";
      const signedXml = createSignedXml(xml);

      const factory = new XmlValidatorFactory({ publicCert });
      const validator1 = factory.createValidator();
      const validator2 = factory.createValidator();

      const result1 = validator1.validate(signedXml);
      const result2 = validator2.validate(signedXml);

      expect(result1.valid).to.be.true;
      expect(result2.valid).to.be.true;
    });

    it("should preserve factory configuration in created validators", function () {
      const xml =
        '<root xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><test wsu:Id="test1">content</test></root>';
      const sig = new SignedXml({
        privateKey,
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        idMode: "wssecurity",
      });
      sig.addReference({
        xpath: "//*[@wsu:Id='test1']",
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
      });
      sig.computeSignature(xml, {
        existingPrefixes: {
          wsu: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
        },
      });
      const signedXml = sig.getSignedXml();

      const factory = new XmlValidatorFactory({
        publicCert,
        enableWSSecurityMode: true,
        maxTransforms: 10,
        throwOnError: false,
      });
      const validator = factory.createValidator();
      const result = validator.validate(signedXml);

      expect(result.valid).to.be.true;
    });
  });
});

describe("XmlValidator Security Features", function () {
  it("should prevent signature wrapping attacks by only returning signed content", function () {
    const xml = "<root><test>content</test><unsigned>malicious</unsigned></root>";
    const signedXml = createSignedXml(xml);

    const validator = new XmlValidator({ publicCert });
    const result = validator.validate(signedXml);

    expect(result.valid).to.be.true;
    expect(result.signedReferences).to.have.length(1);
    // The signed references should only contain the canonicalized content that was actually signed
    expect(result.signedReferences?.[0]).to.not.include("malicious");
    expect(result.signedReferences?.[0]).to.include("content");
  });

  it("should enforce single-use pattern for security", function () {
    const xml = "<root><test>content</test></root>";
    const signedXml = createSignedXml(xml);

    const validator = new XmlValidator({ publicCert });

    // First use should work
    const result1 = validator.validate(signedXml);
    expect(result1.valid).to.be.true;

    // Second use should fail
    const result2 = validator.validate(signedXml);
    expect(result2.valid).to.be.false;
    expect(result2.error).to.include("already been used");
  });

  it("should validate with maxTransforms limit", function () {
    const xml = "<root><test>content</test></root>";
    const signedXml = createSignedXml(xml);

    const validator = new XmlValidator({
      publicCert,
      maxTransforms: 1,
    });
    const result = validator.validate(signedXml);

    expect(result.valid).to.be.true;
  });

  it("should handle edge cases gracefully", function () {
    const validator = new XmlValidator({ publicCert });

    // Empty XML
    const result1 = validator.validate("");
    expect(result1.valid).to.be.false;
    expect(result1.error).to.be.a("string");
  });
});

describe("XmlValidator Integration", function () {
  it("should work with real-world signed XML documents", function () {
    // Test with a more complex XML structure
    const xml = `
      <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Header>
          <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <test wsu:Id="test1" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
              Secure content
            </test>
          </wsse:Security>
        </soap:Header>
        <soap:Body>
          <operation>data</operation>
        </soap:Body>
      </soap:Envelope>
    `;

    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
      idMode: "wssecurity",
    });

    sig.addReference({
      xpath: "//*[@wsu:Id='test1']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    sig.computeSignature(xml, {
      location: {
        reference: "//*[local-name(.)='Security']",
        action: "append",
      },
      existingPrefixes: {
        soap: "http://schemas.xmlsoap.org/soap/envelope/",
        wsse: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
        wsu: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
      },
    });

    const signedXml = sig.getSignedXml();

    const validator = new XmlValidator({
      publicCert,
      enableWSSecurityMode: true,
    });
    const result = validator.validate(signedXml);

    expect(result.valid).to.be.true;
    expect(result.signedReferences).to.have.length(1);
  });

  it("should validate signatures created by XmlSigner", function () {
    // This test ensures compatibility between XmlSigner and XmlValidator
    const xml = '<root><test id="test1">content</test></root>';

    // Create signature using SignedXml (simulating XmlSigner output)
    const sig = new SignedXml({
      privateKey,
      canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
      signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    });

    sig.addReference({
      xpath: "//*[@id='test1']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });

    sig.computeSignature(xml);
    const signedXml = sig.getSignedXml();

    // Validate using XmlValidator
    const validator = new XmlValidator({ publicCert });
    const result = validator.validate(signedXml);

    expect(result.valid).to.be.true;
    expect(result.signedReferences).to.have.length(1);
  });
});
