import { KeyLike, KeyObject, X509Certificate } from "node:crypto";
import { DOMParser } from "@xmldom/xmldom";
import { SignedXml } from "./signed-xml";
import {
  KeySelectorFunction,
  IdAttributeType,
  HashAlgorithmMap,
  TransformAlgorithmMap,
  SignatureAlgorithmMap,
  SignedXmlOptions,
} from "./types";

const DEFAULT_MAX_TRANSFORMS = 4;
const DEFAULT_THROW_ON_ERROR = false;
const DEFAULT_CHECK_CERT_EXPIRATION = true;

export type CertificateKeySelector = {
  /** Public certificate or key to use for validation */
  publicCert: KeyLike;
};

export type KeyInfoKeySelector = {
  /** Function to extract the public key from KeyInfo element */
  getCertFromKeyInfo: (keyInfo?: Node | null) => string | null;
};

export type KeySelector = CertificateKeySelector | KeyInfoKeySelector;

export interface XmlDsigValidatorSecurityOptions {
  /**
   * Maximum number of transforms allowed per Reference element.
   * Limits complexity to prevent denial-of-service attacks.
   * @default {@link DEFAULT_MAX_TRANSFORMS}
   */
  maxTransforms: number;

  /**
   * Check certificate expiration dates during validation.
   * If true, signatures with expired certificates will be considered invalid.
   * This only applies when using KeyInfoKeySelector
   * @default true
   */
  checkCertExpiration: boolean;

  /**
   * Optional truststore of trusted certificates
   * When provided, the certificate used to sign the XML must chain to one of these trusted certificates.
   * These must be PEM or DER encoded X509 certificates
   */
  truststore?: Array<string | Buffer | X509Certificate>;

  /**
   * Signature algorithms allowed during validation.
   *
   * @default {@link SignedXml.getDefaultSignatureAlgorithms()}
   */
  signatureAlgorithms?: SignatureAlgorithmMap;

  /**
   * Hash algorithms allowed during validation.
   *
   * @default {@link SignedXml.getDefaultHashAlgorithms()}
   */
  hashAlgorithms?: HashAlgorithmMap;

  /**
   * Transform algorithms allowed during validation. (This must include canonicalization algorithms)
   *
   * @default all algorithms in {@link SignedXml.getDefaultTransformAlgorithms()}
   */
  transformAlgorithms?: TransformAlgorithmMap;

  /**
   * Canonicalization algorithms allowed during validation.
   *
   * @default all algorithms in {@link SignedXml.getDefaultCanonicalizationAlgorithms()}
   */
  canonicalizationAlgorithms?: TransformAlgorithmMap;
}

/**
 * Common configuration options for XML-DSig validation.
 */
interface XmlDSigValidatorOptions {
  /**
   * Key selector for determining the public key to use for validation.
   */
  keySelector: KeySelector;

  /**
   * Names of XML attributes to treat as element identifiers.
   * Used when resolving URI references in signatures.
   * When passing strings, only the localName is matched, ignoring namespace.
   * To explicitly match attributes without namespaces, use: { localName: "Id", namespaceUri: undefined }
   * @default ["Id", "ID", "id"]
   * @example For WS-Security: [{ localName: "Id", namespaceUri: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" }]
   */
  idAttributes: IdAttributeType[];

  /**
   * Transforms to apply implicitly during canonicalization.
   * Used for specific XML-DSig profiles that require additional transforms.
   */
  implicitTransforms?: ReadonlyArray<string>;

  /**
   * Whether to throw an exception on validation failure.
   * If false, errors are returned in the ValidationResult.
   * @default false
   */
  throwOnError: boolean;

  /**
   * Security options for validation.
   */
  security: Partial<XmlDsigValidatorSecurityOptions>;
}

/**
 * Validation result containing the outcome and signed content.
 */
export interface XmlDSigValidationResult {
  /** Whether the signature is valid */
  valid: boolean;

  /** Error message if validation failed */
  error?: string;

  /**
   * The canonicalized XML content that passed validation.
   * Only available after successful validation.
   * Contains the raw authenticated bytes - users must parse these themselves
   * to ensure they're working with cryptographically verified data only.
   * This prevents signature wrapping attacks.
   */
  signedReferences?: string[];
}

/**
 * A focused API for XML signature validation with enhanced security.
 */
export class XmlDSigValidator {
  private readonly signedXml: SignedXml;
  private readonly options: XmlDSigValidatorOptions;
  private readonly truststore: KeyObject[] | undefined;

  /**
   * Creates a new XmlDSigValidator instance. The instance can be reused for multiple validations.
   *
   * @param options Configuration options for validation
   */
  constructor(options: Partial<XmlDSigValidatorOptions>) {
    if (
      !options.keySelector ||
      (!("publicCert" in options.keySelector) && !("getCertFromKeyInfo" in options.keySelector))
    ) {
      throw new Error("XmlDSigValidator requires a keySelector in options.");
    }
    this.options = {
      ...options,
      keySelector: { ...options.keySelector },
      idAttributes: options.idAttributes ?? SignedXml.getDefaultIdAttributes(),
      throwOnError: options.throwOnError ?? DEFAULT_THROW_ON_ERROR,
      security: {
        maxTransforms: options.security?.maxTransforms ?? DEFAULT_MAX_TRANSFORMS,
        checkCertExpiration: options.security?.checkCertExpiration ?? DEFAULT_CHECK_CERT_EXPIRATION,
        truststore: options.security?.truststore,
        signatureAlgorithms:
          options.security?.signatureAlgorithms ?? SignedXml.getDefaultSignatureAlgorithms(),
        hashAlgorithms: options.security?.hashAlgorithms ?? SignedXml.getDefaultHashAlgorithms(),
        transformAlgorithms:
          options.security?.transformAlgorithms ?? SignedXml.getDefaultTransformAlgorithms(),
        canonicalizationAlgorithms:
          options.security?.canonicalizationAlgorithms ??
          SignedXml.getDefaultCanonicalizationAlgorithms(),
      },
    };

    if ("truststore" in this.options.security && this.options.security.truststore !== undefined) {
      this.truststore = this.options.security.truststore.map((cert) => {
        if (typeof cert === "string" || Buffer.isBuffer(cert)) {
          const x509 = new X509Certificate(cert);
          return x509.publicKey;
        }
        return cert.publicKey;
      });
      if (this.truststore.length === 0) {
        throw new Error("Truststore cannot be empty when provided.");
      }
    }

    this.signedXml = this.createSignedXml();
  }

  /**
   * Validates an XML signature. Static convenience method for one-off validations.
   *
   * @param xml The signed XML document to validate
   * @param options Configuration options for validation
   * @param signatureNode Optional specific Signature node to validate
   */
  public static validate(
    xml: string,
    options: Partial<XmlDSigValidatorOptions>,
    signatureNode?: Node,
  ): XmlDSigValidationResult {
    return new XmlDSigValidator(options).validate(xml, signatureNode);
  }

  /**
   * Validates an XML signature using the pre-configured options.
   *
   * @param xml The signed XML document to validate
   * @param signatureNode Optional specific Signature node to validate
   * @returns Validation result with signed references if successful
   */
  public validate(xml: string, signatureNode?: Node): XmlDSigValidationResult {
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
          return this.handleError("No Signature element found in the provided XML document.");
        } else if (signatureNodes.length > 1) {
          return this.handleError(
            "Multiple Signature elements found in the provided XML document. Please provide the specific signatureNode parameter to validate.",
          );
        }

        // Load the single found signature
        this.signedXml.loadSignature(signatureNodes[0]);
      }

      // Perform cryptographic validation
      const isValid = this.signedXml.checkSignature(xml);

      // Only return signed references if validation succeeded
      const signedReferences = isValid ? this.signedXml.getSignedReferences() : undefined;

      if (!isValid) {
        throw new Error("Signature validation failed");
      }

      return {
        valid: isValid,
        signedReferences,
      };
    } catch (error) {
      if (this.options.throwOnError) {
        // Re-throw the error instead of handling it
        throw error instanceof Error
          ? error
          : new Error(typeof error === "string" ? error : "Unknown validation error");
      }
      return this.handleError(error);
    }
  }

  private createSignedXml(): SignedXml {
    const signedXmlOptions: Partial<SignedXmlOptions> = {
      publicCert: undefined as KeyLike | undefined,
      getCertFromKeyInfo: undefined as KeySelectorFunction | undefined,
      idAttributes: this.options.idAttributes,
      maxTransforms: this.options.security.maxTransforms,
      implicitTransforms: this.options.implicitTransforms,
      allowedSignatureAlgorithms: this.options.security.signatureAlgorithms,
      allowedHashAlgorithms: this.options.security.hashAlgorithms,
      allowedTransformAlgorithms: this.options.security.transformAlgorithms,
      allowedCanonicalizationAlgorithms: this.options.security.canonicalizationAlgorithms,
    };

    // Validate and configure key selector (keySelector is guaranteed to exist from constructor validation)
    if ("publicCert" in this.options.keySelector) {
      signedXmlOptions.publicCert = this.options.keySelector.publicCert;
    } else if ("getCertFromKeyInfo" in this.options.keySelector) {
      if (!this.options.keySelector.getCertFromKeyInfo) {
        throw new Error(
          "XmlDSigValidator requires a valid getCertFromKeyInfo function in options.",
        );
      }

      const getCertFromKeyInfo = this.options.keySelector.getCertFromKeyInfo;
      const truststore = this.truststore;
      const checkCertExpiration = this.options.security.checkCertExpiration;
      signedXmlOptions.getCertFromKeyInfo = (keyInfo?: Node | null): string | null => {
        const certPem = getCertFromKeyInfo(keyInfo);
        if (!certPem) {
          return null;
        }
        if (checkCertExpiration || truststore) {
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
          if (truststore) {
            const isTrusted = truststore.some((trustedCert) => {
              try {
                if (trustedCert.equals(x509.publicKey) || x509.verify(trustedCert)) {
                  return true;
                }
              } catch {
                return false;
              }
            });
            if (!isTrusted) {
              throw new Error("The certificate used to sign the XML is not trusted.");
            }
          }
        }
        return certPem;
      };
    } else {
      throw new Error(
        "XmlDSigValidator requires either a publicCert or getCertFromKeyInfo function in options.",
      );
    }

    return new SignedXml(signedXmlOptions);
  }

  private handleError(error: unknown): XmlDSigValidationResult {
    const errorMessage =
      error instanceof Error
        ? error.message
        : typeof error === "string"
          ? error
          : "Unknown validation error";

    if (this.options.throwOnError) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(errorMessage);
    }

    return {
      valid: false,
      error: errorMessage,
    };
  }
}
