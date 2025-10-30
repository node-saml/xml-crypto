import { KeyLike, X509Certificate } from "node:crypto";
import { DOMParser } from "@xmldom/xmldom";
import { SignedXml } from "./signed-xml";
import {
  KeySelectorFunction,
  SignedXmlOptions,
  VerificationIdAttributeType,
  XmlDSigVerifierOptions,
  XmlDsigVerificationResult,
  TransformAlgorithmURI,
  KeyInfoXmlDSigSecurityOptions,
  KeyInfoKeySelector,
  SharedSecretKeySelector,
  CertificateKeySelector,
  XmlDSigVerifierSecurityOptions,
  KeyInfoXmlDSigVerifierOptions,
  SharedSecretXmlDSigVerifierOptions,
  PublicCertXmlDSigVerifierOptions,
} from "./types";
import { isArrayHasLength } from "./utils";

type ResolvedXmlDSigVerifierOptionsBase = {
  idAttributes: VerificationIdAttributeType[];
  implicitTransforms?: ReadonlyArray<TransformAlgorithmURI>;
  throwOnError: boolean;
};

type ResolvedKeyInfoOptions = ResolvedXmlDSigVerifierOptionsBase & {
  optionsType: "keyinfo";
  keySelector: KeyInfoKeySelector;
  security: Required<KeyInfoXmlDSigSecurityOptions>;
};

type ResolvedCertificateOptions = ResolvedXmlDSigVerifierOptionsBase & {
  optionsType: "certificate";
  keySelector: CertificateKeySelector;
  security: Required<XmlDSigVerifierSecurityOptions>;
};

type ResolvedSharedSecretOptions = ResolvedXmlDSigVerifierOptionsBase & {
  optionsType: "sharedsecret";
  keySelector: SharedSecretKeySelector;
  security: Required<XmlDSigVerifierSecurityOptions>;
};

type ResolvedXmlDsigVerifierOptions =
  | ResolvedKeyInfoOptions
  | ResolvedCertificateOptions
  | ResolvedSharedSecretOptions;

const isResolvedKeyInfoOptions = (
  options: ResolvedXmlDsigVerifierOptions,
): options is ResolvedKeyInfoOptions => options.optionsType === "keyinfo";

const isResolvedPublicCertOptions = (
  options: ResolvedXmlDsigVerifierOptions,
): options is ResolvedCertificateOptions => options.optionsType === "certificate";

const isResolvedSharedSecretOptions = (
  options: ResolvedXmlDsigVerifierOptions,
): options is ResolvedSharedSecretOptions => options.optionsType === "sharedsecret";

const isKeyInfoSelector = (
  options: XmlDSigVerifierOptions,
): options is KeyInfoXmlDSigVerifierOptions => "getCertFromKeyInfo" in options.keySelector;

const isSharedSecretSelector = (
  options: XmlDSigVerifierOptions,
): options is SharedSecretXmlDSigVerifierOptions => "sharedSecretKey" in options.keySelector;

const isPublicCertSelector = (
  options: XmlDSigVerifierOptions,
): options is PublicCertXmlDSigVerifierOptions => "publicCert" in options.keySelector;

/**
 * A focused API for XML signature verification with enhanced security.
 */
export class XmlDSigVerifier {
  private readonly signedXml: SignedXml;
  private readonly options: ResolvedXmlDsigVerifierOptions;

  public static readonly DEFAULT_MAX_TRANSFORMS = 4;
  public static readonly DEFAULT_CHECK_CERT_EXPIRATION = true;
  public static readonly DEFAULT_THROW_ON_ERROR = false;

  /**
   * Creates a new XmlDSigVerifier instance. The instance can be reused for multiple verifications.
   *
   * @param options Configuration options for verification
   */
  constructor(options: XmlDSigVerifierOptions) {
    this.options = XmlDSigVerifier.resolveOptions(options);

    this.signedXml = XmlDSigVerifier.createSignedXml(this.options);
  }

  /**
   * Verifies an XML signature. Static convenience method for one-off verifications.
   *
   * @param xml The signed XML document to validate
   * @param options Configuration options for verification
   * @param signatureNode Optional specific Signature node to validate
   */
  public static verifySignature(
    xml: string,
    options: XmlDSigVerifierOptions,
    signatureNode?: Node,
  ): XmlDsigVerificationResult {
    try {
      return new XmlDSigVerifier(options).verifySignature(xml, signatureNode);
    } catch (error) {
      return XmlDSigVerifier.handleError(
        error,
        options.throwOnError ?? XmlDSigVerifier.DEFAULT_THROW_ON_ERROR,
      );
    }
  }

  /**
   * Validates an XML signature using the pre-configured options.
   *
   * @param xml The signed XML document to validate
   * @param signatureNode Optional specific Signature node to validate
   * @returns Verification result with signed references if successful
   */
  public verifySignature(xml: string, signatureNode?: Node): XmlDsigVerificationResult {
    try {
      // Load the signature node
      if (signatureNode) {
        // Use the provided signature node
        this.signedXml.loadSignature(signatureNode);
      } else {
        // Auto-detect signature if exactly one signature is found in the document
        const doc = new DOMParser().parseFromString(xml, "application/xml");
        const signatureNodes = this.signedXml.findSignatures(doc);

        if (signatureNodes.length === 0) {
          return XmlDSigVerifier.handleError(
            "No Signature element found in the provided XML document.",
            this.options.throwOnError,
          );
        } else if (signatureNodes.length > 1) {
          return XmlDSigVerifier.handleError(
            "Multiple Signature elements found in the provided XML document. Please provide the specific signatureNode parameter to validate.",
            this.options.throwOnError,
          );
        }

        // Load the single found signature
        this.signedXml.loadSignature(signatureNodes[0]);
      }

      // Perform cryptographic verification
      const isValid = this.signedXml.checkSignature(xml);

      if (!isValid) {
        throw new Error("Signature verification failed");
      }

      return {
        success: isValid,
        signedReferences: this.signedXml.getSignedReferences(),
      };
    } catch (error) {
      return XmlDSigVerifier.handleError(error, this.options.throwOnError);
    }
  }

  private static resolveOptions(options: XmlDSigVerifierOptions): ResolvedXmlDsigVerifierOptions {
    const defaults = {
      idAttributes: SignedXml.getDefaultIdAttributes(),
      maxTransforms: XmlDSigVerifier.DEFAULT_MAX_TRANSFORMS,
      checkCertExpiration: XmlDSigVerifier.DEFAULT_CHECK_CERT_EXPIRATION,
      truststore: [],
      signatureAlgorithms: isSharedSecretSelector(options)
        ? SignedXml.getDefaultSymmetricSignatureAlgorithms()
        : SignedXml.getDefaultAsymmetricSignatureAlgorithms(),
      hashAlgorithms: SignedXml.getDefaultHashAlgorithms(),
      transformAlgorithms: SignedXml.getDefaultTransformAlgorithms(),
      canonicalizationAlgorithms: SignedXml.getDefaultCanonicalizationAlgorithms(),
    };

    const baseOptions = {
      idAttributes: options.idAttributes ?? defaults.idAttributes,
      implicitTransforms: options.implicitTransforms,
      throwOnError: options.throwOnError ?? XmlDSigVerifier.DEFAULT_THROW_ON_ERROR,
    };

    const baseSecurity = {
      maxTransforms: options.security?.maxTransforms ?? defaults.maxTransforms,
      signatureAlgorithms: options.security?.signatureAlgorithms ?? defaults.signatureAlgorithms,
      hashAlgorithms: options.security?.hashAlgorithms ?? defaults.hashAlgorithms,
      transformAlgorithms: options.security?.transformAlgorithms ?? defaults.transformAlgorithms,
      canonicalizationAlgorithms:
        options.security?.canonicalizationAlgorithms ?? defaults.canonicalizationAlgorithms,
    };

    if (isKeyInfoSelector(options)) {
      return {
        optionsType: "keyinfo",
        ...baseOptions,
        keySelector: options.keySelector,
        security: {
          ...baseSecurity,
          checkCertExpiration:
            options.security?.checkCertExpiration ?? defaults.checkCertExpiration,
          truststore: options.security?.truststore ?? defaults.truststore,
        },
      };
    } else if (isSharedSecretSelector(options)) {
      return {
        optionsType: "sharedsecret",
        ...baseOptions,
        keySelector: options.keySelector,
        security: baseSecurity,
      };
    } else if (isPublicCertSelector(options)) {
      return {
        optionsType: "certificate",
        ...baseOptions,
        keySelector: options.keySelector,
        security: baseSecurity,
      };
    } else {
      throw new Error("XmlDSigVerifier requires a valid keySelector option.");
    }
  }

  private static createSignedXml(options: ResolvedXmlDsigVerifierOptions): SignedXml {
    const signedXmlOptions: SignedXmlOptions = {
      publicCert: undefined as KeyLike | undefined,
      getCertFromKeyInfo: undefined as KeySelectorFunction | undefined,
      idAttributes: options.idAttributes,
      maxTransforms: options.security.maxTransforms,
      implicitTransforms: options.implicitTransforms,
      allowedSignatureAlgorithms: options.security.signatureAlgorithms,
      allowedHashAlgorithms: options.security.hashAlgorithms,
      allowedTransformAlgorithms: options.security.transformAlgorithms,
      allowedCanonicalizationAlgorithms: options.security.canonicalizationAlgorithms,
    };

    if (isResolvedKeyInfoOptions(options)) {
      const keySelector = options.keySelector;

      if (typeof keySelector.getCertFromKeyInfo !== "function") {
        throw new Error("XmlDSigVerifier requires a valid getCertFromKeyInfo function.");
      }

      const getCertFromKeyInfo = keySelector.getCertFromKeyInfo;
      const truststore = options.security.truststore.map((cert) => {
        if (typeof cert === "string" || Buffer.isBuffer(cert)) {
          const x509 = new X509Certificate(cert);
          return x509.publicKey;
        }
        return cert.publicKey;
      });
      const checkCertExpiration = options.security.checkCertExpiration;

      signedXmlOptions.getCertFromKeyInfo = (keyInfo?: Node | null): string | null => {
        const certPem = getCertFromKeyInfo(keyInfo);
        if (!certPem) {
          return null;
        }

        if (checkCertExpiration || isArrayHasLength(truststore)) {
          const x509 = new X509Certificate(certPem);
          if (checkCertExpiration) {
            const now = new Date();
            if (x509.validTo && new Date(x509.validTo) < now) {
              throw new Error("The certificate used to sign the XML has expired.");
            }
            if (x509.validFrom && new Date(x509.validFrom) > now) {
              throw new Error("The certificate used to sign the XML is not yet valid.");
            }
          }
          if (isArrayHasLength(truststore)) {
            const isTrusted = truststore.some((trustedCert) => {
              if (trustedCert.equals?.(x509.publicKey) || x509.verify(trustedCert)) {
                return true;
              }
              return false;
            });
            if (!isTrusted) {
              throw new Error("The certificate used to sign the XML is not trusted.");
            }
          }
        }
        return certPem;
      };
    } else if (isResolvedPublicCertOptions(options)) {
      signedXmlOptions.publicCert = options.keySelector.publicCert;
    } else if (isResolvedSharedSecretOptions(options)) {
      signedXmlOptions.privateKey = options.keySelector.sharedSecretKey;
    }

    return new SignedXml(signedXmlOptions);
  }

  private static handleError(error: unknown, throwOnError: boolean): XmlDsigVerificationResult {
    if (throwOnError) {
      throw error;
    }

    const errorMessage =
      error instanceof Error ? error.message : `Verification error occurred: ${String(error)}`;

    return {
      success: false,
      error: errorMessage,
    };
  }
}
