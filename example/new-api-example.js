const fs = require("fs");
const { 
  XmlSignerFactory, 
  XmlValidatorFactory,
  SIGNATURE_ALGORITHMS,
  CANONICALIZATION_ALGORITHMS,
  TRANSFORM_ALGORITHMS,
  HASH_ALGORITHMS
} = require("../dist/src/index");

// Example XML to sign
const xml = `<root>
  <data id="data1">Hello World</data>
  <data id="data2">Another element</data>
</root>`;

// Example: Signing with XmlSignerFactory
function signExample() {
  console.log("=== Signing Example (Factory Pattern) ===");

  // Create a factory with common configuration
  const signerFactory = new XmlSignerFactory({
    signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA256,
    canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
    prefix: "ds",
    attributes: { Id: "signature-1" },
    // Include certificate information in KeyInfo for verifier convenience
    keyInfo: {
      content: (args) => {
        const prefix = args?.prefix;
        const cert = fs.readFileSync("./test/static/client_public.pem", "utf8");
        // Extract the certificate content (remove headers/footers and newlines)
        const certContent = cert
          .replace(/-----BEGIN CERTIFICATE-----/, "")
          .replace(/-----END CERTIFICATE-----/, "")
          .replace(/\n/g, "");

        const ns = prefix ? `${prefix}:` : "";
        return `<${ns}X509Data><${ns}X509Certificate>${certContent}</${ns}X509Certificate></${ns}X509Data>`;
      },
      attributes: { Id: "keyinfo-1" },
    },
    // Add default references that will be included in every signer
    references: [
      {
        xpath: "//*[@id='data1']",
        transforms: [TRANSFORM_ALGORITHMS.EXCLUSIVE_C14N],
        digestAlgorithm: HASH_ALGORITHMS.SHA256,
      },
      {
        xpath: "//*[@id='data2']",
        transforms: [TRANSFORM_ALGORITHMS.EXCLUSIVE_C14N],
        digestAlgorithm: HASH_ALGORITHMS.SHA256,
      },
    ],
  });

  // Create a signer from the factory with a private key
  const privateKey = fs.readFileSync("./test/static/client.pem");
  const signer = signerFactory.createSigner(privateKey);

  // Additional references can still be added if needed
  // signer.addReference({
  //   uri: "#additional-element",
  //   transforms: [TRANSFORM_ALGORITHMS.EXCLUSIVE_C14N],
  //   digestAlgorithm: HASH_ALGORITHMS.SHA256,
  // });

  try {
    const signedXml = signer.sign(xml);
    console.log("Signed XML length:", signedXml.length);
    return signedXml;
  } catch (error) {
    console.error("Signing failed:", error.message);
    return null;
  }
}

// Example: Factory with default private key
function signExampleWithDefaultKey() {
  console.log("\n=== Signing Example (Factory with Default Key) ===");

  // Create a factory with a default private key
  const signerFactory = new XmlSignerFactory({
    privateKey: fs.readFileSync("./test/static/client.pem"),
    signatureAlgorithm: SIGNATURE_ALGORITHMS.RSA_SHA256,
    canonicalizationAlgorithm: CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N,
    prefix: "ds",
  });

  // Create a signer without specifying a private key (uses factory default)
  const signer = signerFactory.createSigner();

  // Add references to sign
  signer.addReference({
    xpath: "//*[@id='data1']",
    transforms: [TRANSFORM_ALGORITHMS.EXCLUSIVE_C14N],
    digestAlgorithm: HASH_ALGORITHMS.SHA256,
  });

  try {
    const signedXml = signer.sign(xml);
    console.log("Signed XML with default key, length:", signedXml.length);
    return signedXml;
  } catch (error) {
    console.error("Signing with default key failed:", error.message);
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
        transforms: [
          TRANSFORM_ALGORITHMS.ENVELOPED_SIGNATURE,
          TRANSFORM_ALGORITHMS.EXCLUSIVE_C14N,
        ],
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

// Example: Validation with XmlValidatorFactory
function validateExample(signedXml) {
  console.log("\n=== Validation Example (Factory Pattern) ===");

  // Create a validator factory with configuration
  const validatorFactory = new XmlValidatorFactory({
    publicCert: fs.readFileSync("./test/static/client_public.pem"),
    throwOnError: false, // Return errors in result instead of throwing
  });

  // Create a validator from the factory
  const validator = validatorFactory.createValidator();

  try {
    const result = validator.validate(signedXml);

    console.log("Validation result:", result.valid);
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
    console.error("Validation failed:", error.message);
  }
}

// Example: Validation with different public certificate
function validateExampleWithDifferentCert(signedXml) {
  console.log("\n=== Validation Example (Different Certificate) ===");

  // Create a validator factory with getCertFromKeyInfo function
  const validatorFactory = new XmlValidatorFactory({
    getCertFromKeyInfo: (keyInfo) => {
      // In a real scenario, you would extract the certificate from KeyInfo
      // For this example, we'll just return the test certificate
      return fs.readFileSync("./test/static/client_public.pem", "utf8");
    },
    enableWSSecurityMode: true, // Example of different configuration
    throwOnError: false, // Return errors instead of throwing them
  });

  // Create a validator with a specific certificate (overrides getCertFromKeyInfo)
  const differentCert = fs.readFileSync("./test/static/client_public.pem");
  const validator = validatorFactory.createValidator(differentCert);

  try {
    const result = validator.validate(signedXml);
    console.log("Validation with different cert result:", result.valid);
    if (result.valid && result.signedReferences) {
      console.log("Signed references found:", result.signedReferences.length);
    }
  } catch (error) {
    console.error("Validation with different cert failed:", error.message);
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
  const signedXml = signExample();
  if (signedXml) {
    validateExample(signedXml);
    validateExampleWithDifferentCert(signedXml);
    validateExampleAsync(signedXml);
  }

  // Run other examples
  signExampleWithDefaultKey();
  const envelopedXml = signEnvelopedExample();
  multipleSignaturesExample();
}

module.exports = {
  signExample,
  signExampleWithDefaultKey,
  signEnvelopedExample,
  validateExample,
  validateExampleWithDifferentCert,
  validateExampleAsync,
};
