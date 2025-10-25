const fs = require("fs");
const {
  XmlSignerFactory,
  XmlValidatorFactory,
  SIGNATURE_ALGORITHMS,
  CANONICALIZATION_ALGORITHMS,
  TRANSFORM_ALGORITHMS,
  HASH_ALGORITHMS,
  pemToDer,
} = require("../lib/index");

// Example XML to sign
const xml = `<root>
  <data id="data1">Hello World</data>
  <data id="data2">Another element</data>
  <data customId="data3">Custom ID attribute</data>
</root>`;

// WS-Security example XML
const wsSecurityXml = `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
    </wsse:Security>
  </soap:Header>
  <soap:Body wsu:Id="body-1">
    <data wsu:Id="secure-data">Secure content</data>
  </soap:Body>
</soap:Envelope>`;

// Helper function to extract certificate content for KeyInfo using library utility
function extractCertificateContent(certPath) {
  const cert = fs.readFileSync(certPath, "utf8");
  // Use the library's pemToDer utility for robust PEM parsing
  return pemToDer(cert).toString("base64");
}

// Example: XPath-based signing
function signWithXPathExample() {
  console.log("=== XPath-based Signing Example ===");

  const signerFactory = new XmlSignerFactory({
    signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA256,
    canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
    prefix: "ds",
    attributes: { Id: "xpath-signature" },
    // Include certificate information in KeyInfo for verifier convenience
    keyInfo: {
      content: (args) => {
        const prefix = args?.prefix;
        const certContent = extractCertificateContent("./test/static/client_public.pem");
        const ns = prefix ? `${prefix}:` : "";
        return `<${ns}X509Data><${ns}X509Certificate>${certContent}</${ns}X509Certificate></${ns}X509Data>`;
      },
      attributes: { Id: "keyinfo-xpath" },
    },
  });

  const privateKey = fs.readFileSync("./test/static/client.pem");
  const signer = signerFactory.createSigner(privateKey);

  // Add XPath-based references
  signer.addReference({
    xpath: "//*[@id='data1']", // XPath to select specific element
    transforms: [TRANSFORM_ALGORITHMS.EXCLUSIVE_C14N],
    digestAlgorithm: HASH_ALGORITHMS.SHA256,
    attributes: { Id: "ref-xpath-1", Type: "http://example.com/data-reference" },
  });

  signer.addReference({
    xpath: "//data[@id='data2']", // Different XPath syntax
    transforms: [TRANSFORM_ALGORITHMS.EXCLUSIVE_C14N],
    digestAlgorithm: HASH_ALGORITHMS.SHA256,
    attributes: { Id: "ref-xpath-2" },
  });

  try {
    const signedXml = signer.sign(xml);
    console.log("XPath-signed XML length:", signedXml.length);
    return signedXml;
  } catch (error) {
    console.error("XPath signing failed:", error.message);
    return null;
  }
}

// Example: URI-based signing
function signWithUriExample() {
  console.log("\n=== URI-based Signing Example ===");

  const signerFactory = new XmlSignerFactory({
    signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA256,
    canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
    prefix: "xmldsig",
    attributes: { Id: "uri-signature" },
    keyInfo: {
      content: () => `<KeyName>test-key</KeyName>`, // Simple key name instead of certificate
      attributes: { Id: "keyinfo-uri" },
    },
  });

  const privateKey = fs.readFileSync("./test/static/client.pem");
  const signer = signerFactory.createSigner(privateKey);

  // Add URI-based references
  signer.addReference({
    uri: "#data1", // URI fragment identifier
    transforms: [TRANSFORM_ALGORITHMS.EXCLUSIVE_C14N],
    digestAlgorithm: HASH_ALGORITHMS.SHA256,
    attributes: { Id: "ref-uri-1", Type: "http://example.com/element-ref" },
  });

  signer.addReference({
    uri: "#data2", // Another URI fragment
    transforms: [TRANSFORM_ALGORITHMS.EXCLUSIVE_C14N],
    digestAlgorithm: HASH_ALGORITHMS.SHA256,
    attributes: { Id: "ref-uri-2" },
  });

  try {
    const signedXml = signer.sign(xml);
    console.log("URI-signed XML length:", signedXml.length);
    return signedXml;
  } catch (error) {
    console.error("URI signing failed:", error.message);
    return null;
  }
}

// Example: Custom ID attributes
function signWithCustomIdAttributesExample() {
  console.log("\n=== Custom ID Attributes Example ===");

  const signerFactory = new XmlSignerFactory({
    signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA256,
    canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
    prefix: "ds",
    attributes: { Id: "custom-id-signature" },
    idAttributes: ["customId", "id", "Id"], // Custom ID attributes order
    keyInfo: {
      content: () => `<KeyName>custom-id-key</KeyName>`,
    },
  });

  const privateKey = fs.readFileSync("./test/static/client.pem");
  const signer = signerFactory.createSigner(privateKey);

  // Sign element with custom ID attribute using XPath
  signer.addReference({
    xpath: "//*[@customId='data3']", // XPath to find element with customId="data3"
    transforms: [TRANSFORM_ALGORITHMS.EXCLUSIVE_C14N],
    digestAlgorithm: HASH_ALGORITHMS.SHA256,
    attributes: { Id: "ref-custom-id" },
  });

  try {
    const signedXml = signer.sign(xml);
    console.log("Custom ID attributes signed XML length:", signedXml.length);
    return signedXml;
  } catch (error) {
    console.error("Custom ID attributes signing failed:", error.message);
    return null;
  }
}

// Example: WS-Security mode
function signWithWSSecurityModeExample() {
  console.log("\n=== WS-Security Mode Example ===");

  const signerFactory = new XmlSignerFactory({
    signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA256,
    canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
    prefix: "ds",
    enableWSSecurityMode: true, // Enable WS-Security mode
    attributes: { Id: "ws-security-signature" },
    keyInfo: {
      content: (args) => {
        const prefix = args?.prefix;
        const ns = prefix ? `${prefix}:` : "";
        return `<${ns}KeyName>ws-security-key</${ns}KeyName>`;
      },
      attributes: { Id: "ws-keyinfo" },
    },
    objects: [
      {
        content: `<Timestamp xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
          <Created>2023-01-01T00:00:00Z</Created>
          <Expires>2023-01-01T01:00:00Z</Expires>
        </Timestamp>`,
        attributes: { Id: "timestamp-obj" },
      },
    ],
  });

  const privateKey = fs.readFileSync("./test/static/client.pem");
  const signer = signerFactory.createSigner(privateKey);

  // In WS-Security mode, only wsu:Id attributes are recognized - use XPath with namespace
  signer.addReference({
    xpath: "//*[@*[local-name()='Id' and namespace-uri()='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd']='body-1']",
    transforms: [TRANSFORM_ALGORITHMS.EXCLUSIVE_C14N],
    digestAlgorithm: HASH_ALGORITHMS.SHA256,
    attributes: { Id: "ref-body", Type: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform" },
  });

  signer.addReference({
    xpath: "//*[@*[local-name()='Id' and namespace-uri()='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd']='secure-data']",
    transforms: [TRANSFORM_ALGORITHMS.EXCLUSIVE_C14N],
    digestAlgorithm: HASH_ALGORITHMS.SHA256,
    attributes: { Id: "ref-data" },
  });

  try {
    const signedXml = signer.sign(wsSecurityXml);
    console.log("WS-Security mode signed XML length:", signedXml.length);
    return signedXml;
  } catch (error) {
    console.error("WS-Security mode signing failed:", error.message);
    return null;
  }
}

// Example: Factory with default private key and comprehensive attributes
function signWithAllAttributesExample() {
  console.log("\n=== Comprehensive Attributes Example ===");

  // Create a factory with a default private key and all possible attributes
  const signerFactory = new XmlSignerFactory({
    privateKey: fs.readFileSync("./test/static/client.pem"),
    signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA256,
    canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
    prefix: "ds",
    attributes: { 
      Id: "comprehensive-signature",
      // Note: Custom attributes must be in different namespace in real usage
    },
    keyInfo: {
      content: (args) => {
        const prefix = args?.prefix;
        const certContent = extractCertificateContent("./test/static/client_public.pem");
        const ns = prefix ? `${prefix}:` : "";
        return `<${ns}X509Data><${ns}X509Certificate>${certContent}</${ns}X509Certificate></${ns}X509Data>`;
      },
      attributes: { 
        Id: "comprehensive-keyinfo",
        // Custom attributes would go here in different namespace
      },
    },
    objects: [
      {
        content: `<Properties><Property Target="#data1">This is a property</Property></Properties>`,
        attributes: { 
          Id: "properties-obj",
          MimeType: "text/xml",
          Encoding: "UTF-8",
        },
      },
      {
        content: `<Manifest><Reference URI="#data2"><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha256"/><DigestValue>dummy</DigestValue></Reference></Manifest>`,
        attributes: { 
          Id: "manifest-obj",
          MimeType: "application/xml",
        },
      },
    ],
    location: {
      reference: "/root",
      action: "append",
    },
    existingPrefixes: {
      "custom": "http://example.com/custom",
    },
  });

  // Create a signer without specifying a private key (uses factory default)
  const signer = signerFactory.createSigner();

  // Add references with comprehensive attributes
  signer.addReference({
    xpath: "//*[@id='data1']",
    transforms: [TRANSFORM_ALGORITHMS.EXCLUSIVE_C14N],
    digestAlgorithm: HASH_ALGORITHMS.SHA256,
    inclusiveNamespacesPrefixList: ["custom"],
    attributes: { 
      Id: "ref-comprehensive-1",
      Type: "http://example.com/data-reference",
    },
  });

  signer.addReference({
    uri: "#data2",
    transforms: [TRANSFORM_ALGORITHMS.EXCLUSIVE_C14N],
    digestAlgorithm: HASH_ALGORITHMS.SHA256,
    attributes: { 
      Id: "ref-comprehensive-2",
      Type: "http://example.com/uri-reference",
    },
  });

  try {
    const signedXml = signer.sign(xml);
    console.log("Comprehensive attributes signed XML length:", signedXml.length);
    return signedXml;
  } catch (error) {
    console.error("Comprehensive attributes signing failed:", error.message);
    return null;
  }
}

// Example: Enveloped signature
function signEnvelopedExample() {
  console.log("\n=== Enveloped Signature Example ===");

  const signerFactory = new XmlSignerFactory({
    signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA256,
    canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
    references: [
      {
        uri: "", // Empty URI for enveloped signature
        transforms: [TRANSFORM_ALGORITHMS.ENVELOPED_SIGNATURE, TRANSFORM_ALGORITHMS.EXCLUSIVE_C14N],
        digestAlgorithm: HASH_ALGORITHMS.SHA256,
      },
    ],
  });

  const privateKey = fs.readFileSync("./test/static/client.pem");
  const signer = signerFactory.createSigner(privateKey);

  try {
    const signedXml = signer.sign(xml);
    console.log("Enveloped signed XML length:", signedXml.length);
    return signedXml;
  } catch (error) {
    console.error("Enveloped signing failed:", error.message);
    return null;
  }
}

// Example: Standard validation
function validateStandardExample(signedXml) {
  console.log("\n=== Standard Validation Example ===");

  // Create a validator factory with configuration
  const validatorFactory = new XmlValidatorFactory({
    publicCert: fs.readFileSync("./test/static/client_public.pem"),
    throwOnError: false, // Return errors in result instead of throwing
    maxTransforms: 5, // Allow up to 5 transforms per reference
  });

  // Create a validator from the factory
  const validator = validatorFactory.createValidator();

  try {
    const result = validator.validate(signedXml);

    console.log("Standard validation result:", result.valid);
    if (!result.valid) {
      console.log("Validation error:", result.error);
    }

    // Get the signed content (only available after successful validation)
    if (result.valid && result.signedReferences) {
      console.log("Signed references count:", result.signedReferences.length);
      result.signedReferences.forEach((ref, index) => {
        console.log(`Signed reference ${index + 1} length:`, ref.length);
      });
    }
  } catch (error) {
    console.error("Standard validation failed:", error.message);
  }
}

// Example: Validation with custom ID attributes
function validateWithCustomIdAttributesExample(signedXml) {
  console.log("\n=== Custom ID Attributes Validation Example ===");

  // Create a validator factory with custom ID attributes
  const validatorFactory = new XmlValidatorFactory({
    publicCert: fs.readFileSync("./test/static/client_public.pem"),
    idAttributes: ["customId", "id", "Id"], // Same order as used in signing
    throwOnError: false,
    maxTransforms: 3,
  });

  const validator = validatorFactory.createValidator();

  try {
    const result = validator.validate(signedXml);
    console.log("Custom ID attributes validation result:", result.valid);
    if (result.valid && result.signedReferences) {
      console.log("Custom ID validation - signed references:", result.signedReferences.length);
    } else if (!result.valid) {
      console.log("Custom ID validation error:", result.error);
    }
  } catch (error) {
    console.error("Custom ID attributes validation failed:", error.message);
  }
}

// Example: WS-Security mode validation
function validateWSSecurityModeExample(signedXml) {
  console.log("\n=== WS-Security Mode Validation Example ===");

  // Create a validator factory with WS-Security mode
  const validatorFactory = new XmlValidatorFactory({
    publicCert: fs.readFileSync("./test/static/client_public.pem"),
    enableWSSecurityMode: true, // Enable WS-Security mode
    throwOnError: false,
    maxTransforms: 4,
    implicitTransforms: [TRANSFORM_ALGORITHMS.EXCLUSIVE_C14N], // Default transforms
  });

  const validator = validatorFactory.createValidator();

  try {
    const result = validator.validate(signedXml);
    console.log("WS-Security mode validation result:", result.valid);
    if (result.valid && result.signedReferences) {
      console.log("WS-Security validation - signed references:", result.signedReferences.length);
      result.signedReferences.forEach((ref, index) => {
        console.log(`WS-Security reference ${index + 1} length:`, ref.length);
      });
    } else if (!result.valid) {
      console.log("WS-Security validation error:", result.error);
    }
  } catch (error) {
    console.error("WS-Security mode validation failed:", error.message);
  }
}

// Example: Validation with getCertFromKeyInfo
function validateWithKeyInfoCertExample(signedXml) {
  console.log("\n=== KeyInfo Certificate Extraction Validation Example ===");

  // Create a validator factory with getCertFromKeyInfo function
  const validatorFactory = new XmlValidatorFactory({
    getCertFromKeyInfo: (keyInfo) => {
      console.log("Extracting certificate from KeyInfo...");
      // In a real scenario, you would extract the certificate from KeyInfo
      // For this example, we'll just return the test certificate
      return fs.readFileSync("./test/static/client_public.pem", "utf8");
    },
    throwOnError: false,
    maxTransforms: 6,
  });

  // Create a validator without specifying a certificate (uses getCertFromKeyInfo)
  const validator = validatorFactory.createValidator();

  try {
    const result = validator.validate(signedXml);
    console.log("KeyInfo cert extraction validation result:", result.valid);
    if (result.valid && result.signedReferences) {
      console.log("KeyInfo validation - signed references:", result.signedReferences.length);
    } else if (!result.valid) {
      console.log("KeyInfo validation error:", result.error);
    }
  } catch (error) {
    console.error("KeyInfo cert extraction validation failed:", error.message);
  }
}

// Example: Validation with certificate override
function validateWithCertificateOverrideExample(signedXml) {
  console.log("\n=== Certificate Override Validation Example ===");

  // Create a validator factory with getCertFromKeyInfo function
  const validatorFactory = new XmlValidatorFactory({
    getCertFromKeyInfo: (keyInfo) => {
      // This function will be ignored when we override with a specific certificate
      return "dummy-cert-that-wont-be-used";
    },
    throwOnError: false,
  });

  // Create a validator with a specific certificate (overrides getCertFromKeyInfo)
  const specificCert = fs.readFileSync("./test/static/client_public.pem");
  const validator = validatorFactory.createValidator(specificCert);

  try {
    const result = validator.validate(signedXml);
    console.log("Certificate override validation result:", result.valid);
    if (result.valid && result.signedReferences) {
      console.log("Certificate override - signed references:", result.signedReferences.length);
    } else if (!result.valid) {
      console.log("Certificate override validation error:", result.error);
    }
  } catch (error) {
    console.error("Certificate override validation failed:", error.message);
  }
}

// Example: Async validation
function validateExampleAsync(signedXml) {
  console.log("\n=== Async Validation Example ===");

  const validatorFactory = new XmlValidatorFactory({
    publicCert: fs.readFileSync("./test/static/client_public.pem"),
    throwOnError: false,
  });
  const validator = validatorFactory.createValidator();

  validator.validate(signedXml, (err, result) => {
    if (err) {
      console.error("Async validation error:", err.message);
      return;
    }

    console.log("Async validation result:", result.valid);
    if (result.valid && result.signedReferences) {
      console.log("Async signed references count:", result.signedReferences.length);
    } else if (!result.valid) {
      console.log("Async validation error:", result.error);
    }
  });
}

// Example: Multiple signatures handling
function multipleSignaturesExample() {
  console.log("\n=== Multiple Signatures Example ===");

  // Create two different signed XMLs
  const signerFactory = new XmlSignerFactory({
    signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA256,
    canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
    attributes: { Id: "sig1" },
    references: [
      {
        xpath: "//*[@id='data1']",
        transforms: [TRANSFORM_ALGORITHMS.EXCLUSIVE_C14N],
        digestAlgorithm: HASH_ALGORITHMS.SHA256,
      },
    ],
  });

  const privateKey = fs.readFileSync("./test/static/client.pem");
  const signer1 = signerFactory.createSigner(privateKey);
  const signedOnce = signer1.sign(xml);

  // Add a second signature
  const signer2Factory = new XmlSignerFactory({
    signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA256,
    canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
    attributes: { Id: "sig2" },
    references: [
      {
        xpath: "//*[@id='data2']",
        transforms: [TRANSFORM_ALGORITHMS.EXCLUSIVE_C14N],
        digestAlgorithm: HASH_ALGORITHMS.SHA256,
      },
    ],
  });

  const signer2 = signer2Factory.createSigner(privateKey);
  const signedTwice = signer2.sign(signedOnce);

  console.log("XML with multiple signatures created, length:", signedTwice.length);

  // Now validate a specific signature
  const validatorFactory = new XmlValidatorFactory({
    publicCert: fs.readFileSync("./test/static/client_public.pem"),
  });

  // This will fail because multiple signatures are present
  const validator1 = validatorFactory.createValidator();
  const result1 = validator1.validate(signedTwice);
  console.log("Validation without loading specific signature:", result1.valid);
  if (!result1.valid) {
    console.log("Error:", result1.error);
  }

  // Load a specific signature first
  const { DOMParser } = require("@xmldom/xmldom");
  const xpath = require("xpath");
  const doc = new DOMParser().parseFromString(signedTwice);
  const firstSignature = xpath.select1("//*[local-name(.)='Signature'][@Id='sig1']", doc);

  const validator2 = validatorFactory.createValidator();
  validator2.loadSignature(firstSignature);
  const result2 = validator2.validate(signedTwice);
  console.log("Validation with specific signature loaded:", result2.valid);

  return signedTwice;
}

// Run the examples
if (require.main === module) {
  console.log("🔐 XML Digital Signature API Examples\n");

  // Signing examples
  const xpathSignedXml = signWithXPathExample();
  const uriSignedXml = signWithUriExample();
  const customIdSignedXml = signWithCustomIdAttributesExample();
  const wsSecuritySignedXml = signWithWSSecurityModeExample();
  const comprehensiveSignedXml = signWithAllAttributesExample();

  // Validation examples
  if (xpathSignedXml) {
    validateStandardExample(xpathSignedXml);
    validateWithKeyInfoCertExample(xpathSignedXml);
    validateWithCertificateOverrideExample(xpathSignedXml);
    validateExampleAsync(xpathSignedXml);
  }

  if (customIdSignedXml) {
    validateWithCustomIdAttributesExample(customIdSignedXml);
  }

  if (wsSecuritySignedXml) {
    validateWSSecurityModeExample(wsSecuritySignedXml);
  }

  // Run other examples
  signEnvelopedExample();
  multipleSignaturesExample();
}

module.exports = {
  signWithXPathExample,
  signWithUriExample,
  signWithCustomIdAttributesExample,
  signWithWSSecurityModeExample,
  signWithAllAttributesExample,
  signEnvelopedExample,
  validateStandardExample,
  validateWithCustomIdAttributesExample,
  validateWSSecurityModeExample,
  validateWithKeyInfoCertExample,
  validateWithCertificateOverrideExample,
  validateExampleAsync,
  multipleSignaturesExample,
};
