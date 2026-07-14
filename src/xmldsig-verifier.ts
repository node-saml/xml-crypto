import { KeyLike, X509Certificate } from "node:crypto";
import { SignedXml } from "./signed-xml";
import {
  KeySelectorFunction,
  SignedXmlOptions,
  VerificationIdAttributeType,
  XmlDSigVerifierOptions,
  XmlDsigVerificationResult,
  TransformAlgorithmURI,
  KeyInfoKeySelector,
  SharedSecretKeySelector,
  CertificateKeySelector,
  SignatureAlgorithmMap,
  HashAlgorithmMap,
  TransformAlgorithmMap,
  CanonicalizationAlgorithmMap,
  KeyInfoXmlDSigVerifierOptions,
  SharedSecretXmlDSigVerifierOptions,
  PublicCertXmlDSigVerifierOptions,
  DeferredTrustVerifierOptions,
  DeferredTrustVerificationResult,
  XmlDSigVerifierSecurityOptions,
  SignatureAlgorithm,
} from "./types";
import { isArrayHasLength, parseXml } from "./utils";
import { Sha1, Sha256, Sha512 } from "./hash-algorithms";
import { RsaSha1, RsaSha256, RsaSha256Mgf1, RsaSha512, HmacSha1 } from "./signature-algorithms";
import { C14nCanonicalization, C14nCanonicalizationWithComments } from "./c14n-canonicalization";
import {
  ExclusiveCanonicalization,
  ExclusiveCanonicalizationWithComments,
} from "./exclusive-canonicalization";
import { EnvelopedSignature } from "./enveloped-signature";

type ResolvedXmlDSigVerifierOptionsBase = {
  idAttributes: VerificationIdAttributeType[];
  implicitTransforms?: ReadonlyArray<TransformAlgorithmURI>;
  throwOnError: boolean;
};

/** Resolved security options use maps (what SignedXml expects), not arrays. */
type ResolvedSecurityOptions = {
  maxTransforms: number;
  signatureAlgorithms: SignatureAlgorithmMap;
  hashAlgorithms: HashAlgorithmMap;
  transformAlgorithms: TransformAlgorithmMap;
  canonicalizationAlgorithms: CanonicalizationAlgorithmMap;
};

type ResolvedKeyInfoSecurityOptions = ResolvedSecurityOptions & {
  checkCertExpiration: boolean;
  truststore: Array<string | Buffer | X509Certificate>;
};

type ResolvedKeyInfoOptions = ResolvedXmlDSigVerifierOptionsBase & {
  optionsType: "keyinfo";
  keySelector: KeyInfoKeySelector;
  security: ResolvedKeyInfoSecurityOptions;
};

type ResolvedCertificateOptions = ResolvedXmlDSigVerifierOptionsBase & {
  optionsType: "certificate";
  keySelector: CertificateKeySelector;
  security: ResolvedSecurityOptions;
};

type ResolvedSharedSecretOptions = ResolvedXmlDSigVerifierOptionsBase & {
  optionsType: "sharedsecret";
  keySelector: SharedSecretKeySelector;
  security: ResolvedSecurityOptions;
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

type CertificateHolder = { value: X509Certificate | null };

/**
 * A focused API for XML signature verification with enhanced security.
 */
export class XmlDSigVerifier {
  private readonly signedXml: SignedXml;
  private readonly options: ResolvedXmlDsigVerifierOptions;
  private readonly certificateHolder: CertificateHolder = { value: null };

  public static readonly DEFAULT_MAX_TRANSFORMS = 4;
  public static readonly DEFAULT_CHECK_CERT_EXPIRATION = true;
  public static readonly DEFAULT_THROW_ON_ERROR = false;

  // The default arrays are frozen: they are security allow-lists, and mutating
  // them would silently change the defaults for every verifier in the process.
  // To extend them, spread into a new array: [...XmlDSigVerifier.defaultHashAlgorithms, MyCustom]
  // TODO(v7): remove SHA-1 from default hash algorithms.
  static readonly defaultHashAlgorithms = Object.freeze([Sha1, Sha256, Sha512]);
  static readonly defaultAsymmetricSignatureAlgorithms = Object.freeze([
    // TODO(v7): remove RSA-SHA1 from default signature algorithms.
    RsaSha1,
    RsaSha256,
    RsaSha256Mgf1,
    RsaSha512,
  ]);
  // TODO: add HMAC-SHA256 support and make it the default instead of HMAC-SHA1.
  static readonly defaultSymmetricSignatureAlgorithms = Object.freeze([HmacSha1]);
  static readonly defaultCanonicalizationAlgorithms = Object.freeze([
    C14nCanonicalization,
    C14nCanonicalizationWithComments,
    ExclusiveCanonicalization,
    ExclusiveCanonicalizationWithComments,
  ]);
  static readonly defaultTransformAlgorithms = Object.freeze([
    ...XmlDSigVerifier.defaultCanonicalizationAlgorithms,
    EnvelopedSignature,
  ]);

  private static readonly symmetricSignatureAlgorithmURIs = new Set<string>(
    XmlDSigVerifier.defaultSymmetricSignatureAlgorithms.map((Ctor) =>
      new Ctor().getAlgorithmName(),
    ),
  );

  private static toAlgorithmMap<T extends { getAlgorithmName(): string }>(
    constructors: ReadonlyArray<new () => T>,
  ): Record<string, new () => T> {
    const map: Record<string, new () => T> = {};
    for (const Ctor of constructors) {
      const instance = new Ctor();
      map[instance.getAlgorithmName()] = Ctor;
    }
    return map;
  }

  /**
   * Build the algorithm-map portion of the resolved security options. Shared by
   * the strict (`resolveOptions`) and deferred-trust (`createDeferredTrustSignedXml`)
   * paths so the four allowed-algorithm maps don't drift between them.
   */
  /**
   * Key-confusion guard shared by the strict and deferred-trust paths.
   *
   * Verifying an HMAC signature against public certificate material is forgeable
   * by anyone who knows the (public) certificate, so symmetric algorithms are
   * only allowed with the `sharedSecretKey` selector — and there, asymmetric
   * algorithms are rejected so the two families can never be enabled together.
   * Detection is by the known symmetric URIs (HMAC); custom algorithms outside
   * that set are assumed asymmetric.
   */
  private static assertNoSignatureAlgorithmKeyConfusion(
    signatureAlgorithms: SignatureAlgorithmMap,
    expectSymmetric: boolean,
    context: string,
  ): void {
    for (const uri of Object.keys(signatureAlgorithms)) {
      const isSymmetric = XmlDSigVerifier.symmetricSignatureAlgorithmURIs.has(uri);
      if (isSymmetric && !expectSymmetric) {
        throw new Error(
          `${context} does not support symmetric signature algorithms (got '${uri}'). ` +
            "Verifying an HMAC signature against public certificate material is a key-confusion " +
            "vulnerability; use the sharedSecretKey key selector for HMAC.",
        );
      }
      if (!isSymmetric && expectSymmetric) {
        throw new Error(
          `${context} only supports symmetric (HMAC) signature algorithms (got '${uri}'). ` +
            "Enabling asymmetric algorithms alongside a shared secret is a key-confusion footgun; " +
            "use the publicCert or getCertFromKeyInfo key selector for asymmetric signatures.",
        );
      }
    }
  }

  private static resolveBaseSecurityOptions(
    security: XmlDSigVerifierSecurityOptions | undefined,
    defaultSignatureAlgorithms: ReadonlyArray<new () => SignatureAlgorithm>,
  ): ResolvedSecurityOptions {
    return {
      maxTransforms: security?.maxTransforms ?? XmlDSigVerifier.DEFAULT_MAX_TRANSFORMS,
      signatureAlgorithms: XmlDSigVerifier.toAlgorithmMap(
        security?.signatureAlgorithms ?? defaultSignatureAlgorithms,
      ),
      hashAlgorithms: XmlDSigVerifier.toAlgorithmMap(
        security?.hashAlgorithms ?? XmlDSigVerifier.defaultHashAlgorithms,
      ),
      transformAlgorithms: XmlDSigVerifier.toAlgorithmMap(
        security?.transformAlgorithms ?? XmlDSigVerifier.defaultTransformAlgorithms,
      ),
      canonicalizationAlgorithms: XmlDSigVerifier.toAlgorithmMap(
        security?.canonicalizationAlgorithms ?? XmlDSigVerifier.defaultCanonicalizationAlgorithms,
      ),
    };
  }

  /**
   * Creates a new XmlDSigVerifier instance. The instance can be reused for multiple verifications.
   *
   * @param options Configuration options for verification
   */
  constructor(options: XmlDSigVerifierOptions) {
    this.options = XmlDSigVerifier.resolveOptions(options);

    this.signedXml = XmlDSigVerifier.createSignedXml(this.options, this.certificateHolder);
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
   * Verifies the cryptographic signature against the certificate embedded in
   * `<KeyInfo>` and returns that certificate WITHOUT establishing trust.
   *
   * Use this ONLY when trust will be established out-of-band, for example:
   *   - XAdES-LTV / XAdES-A archival flows
   *   - EU Trusted List (TSL) qualified-signature validation services
   *   - UBL e-invoicing with a downstream counterparty registry
   *   - Storing the cert for non-repudiation audit, validated later
   *
   * For SAML, SSO, or any flow where the signing identity must be authenticated
   * at verification time, use {@link XmlDSigVerifier.verifySignature} with a
   * truststore instead.
   *
   * SECURITY: The returned `untrustedCertificate` is attacker-controlled. A
   * passing result with no follow-up trust check provides NO security
   * guarantee. An attacker who can supply the document can sign it with their
   * own keypair and the math will still verify.
   *
   * @param xml The signed XML document to verify
   * @param options Configuration options (no truststore, no expiration check)
   * @param signatureNode Optional specific Signature node to verify
   */
  public static extractAndVerify(
    xml: string,
    options: DeferredTrustVerifierOptions,
    signatureNode?: Node,
  ): DeferredTrustVerificationResult {
    const throwOnError = options.throwOnError ?? XmlDSigVerifier.DEFAULT_THROW_ON_ERROR;
    try {
      if (typeof options.keySelector?.getCertFromKeyInfo !== "function") {
        throw new Error(
          "XmlDSigVerifier.extractAndVerify requires a valid getCertFromKeyInfo function.",
        );
      }
      if (options.idAttributes != null && !isArrayHasLength(options.idAttributes)) {
        throw new Error(
          "XmlDSigVerifier.extractAndVerify: 'idAttributes' must contain at least one entry. " +
            "An empty array means no reference URIs can be resolved and verification would always fail.",
        );
      }

      // Reject trust-related options at runtime too (the types already exclude
      // them): silently ignoring a truststore here would let callers believe
      // trust was enforced when it was not.
      const security = options.security as Record<string, unknown> | undefined;
      if (security?.truststore != null) {
        throw new Error(
          "XmlDSigVerifier.extractAndVerify does not support 'truststore'. Deferred-trust " +
            "verification performs no trust check; use verifySignature with getCertFromKeyInfo " +
            "to enforce a truststore.",
        );
      }
      if (security?.checkCertExpiration != null) {
        throw new Error(
          "XmlDSigVerifier.extractAndVerify does not support 'checkCertExpiration'. Deferred-trust " +
            "verification performs no certificate validation; use verifySignature with " +
            "getCertFromKeyInfo to check expiration.",
        );
      }

      const certificateHolder: CertificateHolder = { value: null };
      const signedXml = XmlDSigVerifier.createDeferredTrustSignedXml(options, certificateHolder);

      if (signatureNode) {
        signedXml.loadSignature(signatureNode);
      } else {
        const doc = parseXml(xml);
        const signatureNodes = signedXml.findSignatures(doc);
        if (signatureNodes.length === 0) {
          return XmlDSigVerifier.handleDeferredTrustError(
            "No Signature element found in the provided XML document.",
            throwOnError,
          );
        }
        if (signatureNodes.length > 1) {
          return XmlDSigVerifier.handleDeferredTrustError(
            "Multiple Signature elements found in the provided XML document. Please provide the specific signatureNode parameter to verify.",
            throwOnError,
          );
        }
        signedXml.loadSignature(signatureNodes[0]);
      }

      const isValid = signedXml.checkSignature(xml);
      if (!isValid) {
        throw new Error("Signature verification failed");
      }

      if (certificateHolder.value == null) {
        // checkSignature succeeded, but the keyInfo callback never produced a
        // certificate. This is structurally possible if a caller's
        // getCertFromKeyInfo returns null and the signature still verifies via
        // some other path; we refuse to claim success without a cert to hand
        // back.
        throw new Error(
          "Signature math verified, but no certificate was extracted from <KeyInfo>; cannot return an untrustedCertificate.",
        );
      }

      return {
        success: true,
        signatureValid: true,
        untrustedCertificate: certificateHolder.value,
        signedReferences: signedXml.getSignedReferences(),
      };
    } catch (error) {
      return XmlDSigVerifier.handleDeferredTrustError(error, throwOnError);
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
    // Clear any certificate captured by a previous verification on this instance.
    this.certificateHolder.value = null;
    try {
      // Load the signature node
      if (signatureNode) {
        // Use the provided signature node
        this.signedXml.loadSignature(signatureNode);
      } else {
        // Auto-detect signature if exactly one signature is found in the document
        const doc = parseXml(xml);
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

      const result: XmlDsigVerificationResult = {
        success: isValid,
        signedReferences: this.signedXml.getSignedReferences(),
      };
      if (this.certificateHolder.value != null) {
        result.certificate = this.certificateHolder.value;
      }
      return result;
    } catch (error) {
      return XmlDSigVerifier.handleError(error, this.options.throwOnError);
    }
  }

  private static resolveOptions(options: XmlDSigVerifierOptions): ResolvedXmlDsigVerifierOptions {
    const keySelector: unknown = options.keySelector;
    if (keySelector == null || typeof keySelector !== "object") {
      throw new Error("XmlDSigVerifier requires a valid keySelector option.");
    }
    const providedSelectors = ["publicCert", "getCertFromKeyInfo", "sharedSecretKey"].filter(
      (key) => key in keySelector,
    );
    if (providedSelectors.length === 0) {
      throw new Error("XmlDSigVerifier requires a valid keySelector option.");
    }
    if (providedSelectors.length > 1) {
      throw new Error(
        "XmlDSigVerifier: keySelector must contain exactly one of 'publicCert', " +
          `'getCertFromKeyInfo', or 'sharedSecretKey' — got ${providedSelectors.join(" and ")}.`,
      );
    }

    if (!isKeyInfoSelector(options)) {
      const security = options.security as Record<string, unknown> | undefined;
      if (security?.checkCertExpiration != null) {
        throw new Error("checkCertExpiration is only supported with getCertFromKeyInfo");
      }
      if (security?.truststore != null) {
        throw new Error("truststore is only supported with getCertFromKeyInfo");
      }
    }

    if (options.idAttributes != null && !isArrayHasLength(options.idAttributes)) {
      throw new Error(
        "XmlDSigVerifier: 'idAttributes' must contain at least one entry. " +
          "An empty array means no reference URIs can be resolved and verification " +
          "would always fail. Omit the option to use the default (['Id', 'ID', 'id']).",
      );
    }

    const defaultSignatureAlgorithms = isSharedSecretSelector(options)
      ? XmlDSigVerifier.defaultSymmetricSignatureAlgorithms
      : XmlDSigVerifier.defaultAsymmetricSignatureAlgorithms;

    const baseOptions = {
      idAttributes: options.idAttributes ?? SignedXml.getDefaultIdAttributes(),
      implicitTransforms: options.implicitTransforms,
      throwOnError: options.throwOnError ?? XmlDSigVerifier.DEFAULT_THROW_ON_ERROR,
    };

    const baseSecurity: ResolvedSecurityOptions = XmlDSigVerifier.resolveBaseSecurityOptions(
      options.security,
      defaultSignatureAlgorithms,
    );

    XmlDSigVerifier.assertNoSignatureAlgorithmKeyConfusion(
      baseSecurity.signatureAlgorithms,
      isSharedSecretSelector(options),
      isSharedSecretSelector(options)
        ? "XmlDSigVerifier with the sharedSecretKey key selector"
        : "XmlDSigVerifier with an asymmetric key selector",
    );

    if (isKeyInfoSelector(options)) {
      const truststore = options.security?.truststore;
      if (truststore == null) {
        throw new Error(
          "XmlDSigVerifier: 'truststore' is required when verifying with getCertFromKeyInfo. " +
            "Without a truststore, the verifier would trust whatever certificate the document " +
            "claims to be signed with — which is attacker-controlled. Provide a non-empty array " +
            "of trust anchors (PEM, DER, or X509Certificate).",
        );
      }
      if (!isArrayHasLength(truststore)) {
        throw new Error(
          "XmlDSigVerifier: 'truststore' must contain at least one trusted certificate. " +
            "An empty array is not a supported way to bypass trust validation.",
        );
      }
      return {
        optionsType: "keyinfo",
        ...baseOptions,
        keySelector: options.keySelector,
        security: {
          ...baseSecurity,
          checkCertExpiration:
            options.security?.checkCertExpiration ?? XmlDSigVerifier.DEFAULT_CHECK_CERT_EXPIRATION,
          truststore,
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

  private static createSignedXml(
    options: ResolvedXmlDsigVerifierOptions,
    certificateHolder: CertificateHolder,
  ): SignedXml {
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
        const isTrusted = truststore.some(
          (trustedCert) => trustedCert.equals(x509.publicKey) || x509.verify(trustedCert),
        );
        if (!isTrusted) {
          throw new Error(
            `The certificate used to sign the XML is not trusted. ` +
              `Subject="${x509.subject}", Issuer="${x509.issuer}". ` +
              `xml-crypto uses a direct-trust model — the signing certificate must either ` +
              `match a truststore entry by public key (cert pinning) or be directly signed by ` +
              `a truststore entry (single-hop CA). Full PKIX path validation is not performed; ` +
              `if you have a multi-hop chain, add the relevant intermediates to the truststore ` +
              `or pre-validate the chain externally and pass the leaf certificate.`,
          );
        }
        certificateHolder.value = x509;
        // Return the normalized PEM of the cert we just parsed and verified
        // instead of the original certPem string. The user-supplied PEM can
        // contain multiple certificates or other surprises; downstream signature
        // verification re-parses whatever we return, and we want that re-parse
        // to yield the same cert we validated against the truststore.
        return x509.toString();
      };
    } else if (isResolvedPublicCertOptions(options)) {
      signedXmlOptions.publicCert = options.keySelector.publicCert;
    } else if (isResolvedSharedSecretOptions(options)) {
      signedXmlOptions.privateKey = options.keySelector.sharedSecretKey;
    }

    return new SignedXml(signedXmlOptions);
  }

  private static createDeferredTrustSignedXml(
    options: DeferredTrustVerifierOptions,
    certificateHolder: CertificateHolder,
  ): SignedXml {
    const baseSecurity = XmlDSigVerifier.resolveBaseSecurityOptions(
      options.security,
      XmlDSigVerifier.defaultAsymmetricSignatureAlgorithms,
    );

    // Deferred-trust verifies against the public key extracted from the X.509
    // cert in <KeyInfo>, so symmetric algorithms must be rejected.
    XmlDSigVerifier.assertNoSignatureAlgorithmKeyConfusion(
      baseSecurity.signatureAlgorithms,
      false,
      "XmlDSigVerifier.extractAndVerify",
    );

    const getCertFromKeyInfo = options.keySelector.getCertFromKeyInfo;

    const signedXmlOptions: SignedXmlOptions = {
      idAttributes: options.idAttributes ?? SignedXml.getDefaultIdAttributes(),
      maxTransforms: baseSecurity.maxTransforms,
      implicitTransforms: options.implicitTransforms,
      allowedSignatureAlgorithms: baseSecurity.signatureAlgorithms,
      allowedHashAlgorithms: baseSecurity.hashAlgorithms,
      allowedTransformAlgorithms: baseSecurity.transformAlgorithms,
      allowedCanonicalizationAlgorithms: baseSecurity.canonicalizationAlgorithms,
      getCertFromKeyInfo: (keyInfo?: Node | null): string | null => {
        const certPem = getCertFromKeyInfo(keyInfo);
        if (!certPem) {
          return null;
        }
        // Math-only path: parse the cert so we can surface it on the result,
        // but DO NOT check expiration or consult any truststore. Trust is the
        // caller's responsibility.
        const x509 = new X509Certificate(certPem);
        certificateHolder.value = x509;
        // Return the normalized PEM of the parsed cert (not the original
        // certPem) so the cert surfaced as `untrustedCertificate` is exactly
        // the one downstream signature verification re-parses. A multi-cert
        // PEM string would otherwise let the two diverge.
        return x509.toString();
      },
    };

    return new SignedXml(signedXmlOptions);
  }

  private static handleError(error: unknown, throwOnError: boolean): XmlDsigVerificationResult {
    if (throwOnError) {
      throw error instanceof Error ? error : new Error(String(error));
    }

    const errorMessage =
      error instanceof Error ? error.message : `Verification error occurred: ${String(error)}`;

    return {
      success: false,
      error: errorMessage,
    };
  }

  private static handleDeferredTrustError(
    error: unknown,
    throwOnError: boolean,
  ): DeferredTrustVerificationResult {
    if (throwOnError) {
      throw error instanceof Error ? error : new Error(String(error));
    }

    const errorMessage =
      error instanceof Error ? error.message : `Verification error occurred: ${String(error)}`;

    return {
      success: false,
      signatureValid: false,
      error: errorMessage,
    };
  }
}
