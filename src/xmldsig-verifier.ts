import { KeyLike, KeyObject, X509Certificate } from "node:crypto";
import { DOMParser } from "@xmldom/xmldom";
import { SignedXml } from "./signed-xml";
import {
  KeySelectorFunction,
  SignedXmlOptions,
  VerificationIdAttributeType,
  KeySelector,
  XmlDSigVerifierSecurityOptions,
  XmlDSigVerifierOptions,
  XmlDsigVerificationResult,
} from "./types";
import { isArrayHasLength } from "./utils";

const DEFAULT_MAX_TRANSFORMS = 4;
const DEFAULT_THROW_ON_ERROR = false;
const DEFAULT_CHECK_CERT_EXPIRATION = true;

type ResolvedXmlDsigVerifierOptions = {
  keySelector: KeySelector;
  idAttributes: VerificationIdAttributeType[];
  implicitTransforms?: ReadonlyArray<string>;
  throwOnError: boolean;
  security: Required<XmlDSigVerifierSecurityOptions>;
};

/**
 * A focused API for XML signature verification with enhanced security.
 */
export class XmlDSigVerifier {
  private readonly signedXml: SignedXml;
  private readonly options: ResolvedXmlDsigVerifierOptions;
  private readonly truststore: KeyObject[] = [];

  /**
   * Creates a new XmlDSigVerifier instance. The instance can be reused for multiple verifications.
   *
   * @param options Configuration options for verification
   */
  constructor(options: XmlDSigVerifierOptions) {
    if (
      !options.keySelector ||
      (!("publicCert" in options.keySelector) && !("getCertFromKeyInfo" in options.keySelector))
    ) {
      throw new Error("XmlDSigVerifier requires a keySelector in options.");
    }
    this.options = {
      ...options,
      keySelector: { ...options.keySelector },
      idAttributes: isArrayHasLength(options.idAttributes)
        ? options.idAttributes
        : SignedXml.getDefaultIdAttributes(),
      throwOnError: options.throwOnError ?? DEFAULT_THROW_ON_ERROR,
      security: {
        maxTransforms: options.security?.maxTransforms ?? DEFAULT_MAX_TRANSFORMS,
        checkCertExpiration: options.security?.checkCertExpiration ?? DEFAULT_CHECK_CERT_EXPIRATION,
        truststore: options.security?.truststore ?? [],
        signatureAlgorithms:
          options.security?.signatureAlgorithms ?? SignedXml.getDefaultSignatureAlgorithms(),
        hashAlgorithms: options.security?.hashAlgorithms ?? SignedXml.getDefaultDigestAlgorithms(),
        transformAlgorithms:
          options.security?.transformAlgorithms ?? SignedXml.getDefaultTransformAlgorithms(),
        canonicalizationAlgorithms:
          options.security?.canonicalizationAlgorithms ??
          SignedXml.getDefaultCanonicalizationAlgorithms(),
      },
    };

    this.truststore = this.options.security.truststore.map((cert) => {
      if (typeof cert === "string" || Buffer.isBuffer(cert)) {
        const x509 = new X509Certificate(cert);
        return x509.publicKey;
      }
      return cert.publicKey;
    });

    this.signedXml = this.createSignedXml();
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
      return XmlDSigVerifier.handleError(error, options.throwOnError ?? DEFAULT_THROW_ON_ERROR);
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

  private createSignedXml(): SignedXml {
    const signedXmlOptions: SignedXmlOptions = {
      publicCert: undefined as KeyLike | undefined,
      getCertFromKeyInfo: undefined as KeySelectorFunction | undefined,
      idAttributes: this.options.idAttributes,
      maxTransforms: this.options.security.maxTransforms,
      implicitTransforms: this.options.implicitTransforms,
      allowedSignatureAlgorithms: this.options.security.signatureAlgorithms,
      allowedDigestAlgorithms: this.options.security.hashAlgorithms,
      allowedTransformAlgorithms: this.options.security.transformAlgorithms,
      allowedCanonicalizationAlgorithms: this.options.security.canonicalizationAlgorithms,
    };

    // Validate and configure key selector (keySelector is guaranteed to exist from constructor verification)
    if ("publicCert" in this.options.keySelector) {
      signedXmlOptions.publicCert = this.options.keySelector.publicCert;
    } else if ("getCertFromKeyInfo" in this.options.keySelector) {
      if (!this.options.keySelector.getCertFromKeyInfo) {
        throw new Error("XmlDSigVerifier requires a valid getCertFromKeyInfo function in options.");
      }

      const getCertFromKeyInfo = this.options.keySelector.getCertFromKeyInfo;
      const truststore = this.truststore;
      const checkCertExpiration = this.options.security.checkCertExpiration;
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
        "XmlDSigVerifier requires either a publicCert or getCertFromKeyInfo function in options.",
      );
    }

    return new SignedXml(signedXmlOptions);
  }

  private static handleError(error: unknown, throwOnError: boolean): XmlDsigVerificationResult {
    const errorMessage =
      error instanceof Error
        ? error.message
        : typeof error === "string"
          ? error
          : "Unknown verification error";

    if (throwOnError) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(errorMessage);
    }

    return {
      success: false,
      error: errorMessage,
    };
  }
}
