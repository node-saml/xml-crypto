import type { ErrorFirstCallback } from "./types";
import { SignedXml } from "./signed-xml";
import * as crypto from "crypto";
import { DOMParser } from "@xmldom/xmldom";

const DEFAULT_ID_ATTRIBUTES = ["Id", "ID", "id"];
const DEFAULT_MAX_TRANSFORMS = 4;
const DEFAULT_THROW_ON_ERROR = false;

interface BaseXmlValidatorOptionsCommon {
  throwOnError?: boolean;
  maxTransforms?: number;
  implicitTransforms?: ReadonlyArray<string>;
}

/**
 * When WSSecurity mode is disabled, users can specify custom ID attributes.
 */
export interface BaseXmlValidatorOptionsWithId extends BaseXmlValidatorOptionsCommon {
  enableWSSecurityMode?: false;
  idAttributes?: string[];
}

/**
 * When WSSecurity mode is enabled, ID attributes are fixed to WS-Security standards. (wsu:Id)
 * Accepting idAttributes in this mode is disallowed to prevent confusion.
 */
export interface BaseXmlValidatorOptionsWS extends BaseXmlValidatorOptionsCommon {
  enableWSSecurityMode: true;
  idAttributes?: never;
}

export type BaseXmlValidatorOptions = BaseXmlValidatorOptionsWithId | BaseXmlValidatorOptionsWS;

/**
 * Validation using a provided public certificate.
 * If user provides this we assume they want to validate exactly against it, not whatever is in KeyInfo.
 */
export type PublicCertXmlValidatorOptions = BaseXmlValidatorOptions & {
  publicCert: crypto.KeyLike;
};

/**
 * When the user does not know the public certificate in advance, they can provide a function to extract it from KeyInfo.
 */
export type KeyInfoXmlValidatorOptions = BaseXmlValidatorOptions & {
  getCertFromKeyInfo: (keyInfo?: Node | null) => string | null;
};

export type XmlValidatorOptions = PublicCertXmlValidatorOptions | KeyInfoXmlValidatorOptions;

/**
 * Validation result containing the outcome and signed content.
 */
export interface ValidationResult {
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
export class XmlValidator {
  private readonly signedXml: SignedXml;
  private readonly options: Required<Pick<XmlValidatorOptions, "maxTransforms" | "throwOnError">>;
  private wasUsed: boolean = false;
  private signatureLoaded: boolean = false;

  /**
   * Creates a new XmlValidator instance.
   * It is recommended to use XmlValidatorFactory for creating instances.
   *
   * @param options Configuration options for validation
   */
  constructor(options: XmlValidatorOptions) {
    // Create SignedXml instance
    if ("publicCert" in options && options.publicCert) {
      this.signedXml = new SignedXml({
        publicCert: options.publicCert,
        idMode: options.enableWSSecurityMode ? "wssecurity" : undefined,
        implicitTransforms: options.implicitTransforms,
      });
    } else if ("getCertFromKeyInfo" in options && options.getCertFromKeyInfo) {
      this.signedXml = new SignedXml({
        getCertFromKeyInfo: options.getCertFromKeyInfo,
        idMode: options.enableWSSecurityMode ? "wssecurity" : undefined,
        implicitTransforms: options.implicitTransforms,
      });
    } else {
      throw new Error(
        "XmlValidator requires either a publicCert or getCertFromKeyInfo function in options.",
      );
    }

    // Force the SignedXml to use the appropriate ID attributes
    this.signedXml.idAttributes = options.enableWSSecurityMode
      ? ["Id"]
      : options.idAttributes && options.idAttributes.length > 0
        ? options.idAttributes
        : DEFAULT_ID_ATTRIBUTES;

    // Set defaults for security options
    this.options = {
      maxTransforms: options.maxTransforms ?? DEFAULT_MAX_TRANSFORMS,
      throwOnError: options.throwOnError ?? DEFAULT_THROW_ON_ERROR,
    };
  }

  /**
   * Allow the user to explicitly set which signature to validate.
   * Useful when multiple signatures are present in the document.
   * @param signatureNode The Signature element to validate
   */
  public loadSignature(signatureNode: Node): void {
    if (this.signatureLoaded) {
      throw new Error("A signature has already been loaded into this XmlValidator instance.");
    }
    this.signedXml.loadSignature(signatureNode);
    this.signatureLoaded = true;
  }

  /**
   * Validates an XML signature synchronously.
   *
   * @param xml The signed XML document to validate
   * @returns Validation result with signed references if successful
   */
  public validate(xml: string): ValidationResult;

  /**
   * Validates an XML signature asynchronously.
   *
   * @param xml The signed XML document to validate
   * @param callback Callback function to handle the result
   */
  public validate(xml: string, callback: ErrorFirstCallback<ValidationResult>): void;

  public validate(
    xml: string,
    callback?: ErrorFirstCallback<ValidationResult>,
  ): ValidationResult | void {
    if (this.wasUsed) {
      return this.handleError(
        "This XmlValidator instance has already been used. Create a new instance to validate another document. ",
        callback,
      );
    }

    // Check if a signature has been loaded
    if (!this.signatureLoaded) {
      // We will load the signature if exactly one signature is found in the document
      const doc = new DOMParser().parseFromString(xml, "application/xml");
      const signatureNodes = this.signedXml.findSignatures(doc);

      if (signatureNodes.length === 0) {
        return this.handleError(
          "No Signature element found in the provided XML document.",
          callback,
        );
      } else if (signatureNodes.length > 1) {
        return this.handleError(
          "Multiple Signature elements found in the provided XML document. Please load the desired signature explicitly using loadSignature().",
          callback,
        );
      }

      // Load the single found signature
      this.signedXml.loadSignature(signatureNodes[0]);
    }

    this.wasUsed = true;

    try {
      if (callback) {
        // ASYNCHRONOUS PATH
        this.signedXml.checkSignature(xml, (error, isValid) => {
          if (error) {
            callback(null, { valid: false, error: error.message });
            return;
          }

          // Only return signed references if validation succeeded
          const signedReferences = isValid ? this.signedXml.getSignedReferences() : undefined;

          callback(null, {
            valid: isValid || false,
            signedReferences,
          });
        });
        // The main function returns void in async mode
        return;
      } else {
        // SYNCHRONOUS PATH
        // Perform cryptographic validation
        const isValid = this.signedXml.checkSignature(xml);

        // Only return signed references if validation succeeded
        const signedReferences = isValid ? this.signedXml.getSignedReferences() : undefined;

        return {
          valid: isValid,
          signedReferences,
        };
      }
    } catch (error) {
      return this.handleError(error, callback);
    }
  }

  private handleError(
    error: unknown,
    callback?: ErrorFirstCallback<ValidationResult>,
  ): ValidationResult | void {
    if (this.options.throwOnError) {
      throw error;
    }

    const result = {
      valid: false,
      error:
        error instanceof Error
          ? error.message
          : typeof error === "string"
            ? error
            : "Unknown validation error",
    };
    if (callback) {
      callback(null, result);
      return;
    }
    return result;
  }
}

/**
 * Factory for creating XmlValidator instances with consistent configuration.
 * Recommended way to create validators to ensure consistent security settings.
 */
export class XmlValidatorFactory {
  private readonly options: XmlValidatorOptions;

  /**
   * Creates a new XmlValidatorFactory with default security settings.
   *
   * @param options Configuration options applied to all validators created by this factory
   */
  constructor(options: XmlValidatorOptions) {
    this.options = { ...options };
  }

  /**
   * Creates a new XmlValidator instance with the factory's configuration.
   *
   * @returns A new, single-use XmlValidator instance
   */
  createValidator(): XmlValidator;

  /**
   * Creates a new XmlValidator instance with a specific public certificate,
   * overriding the factory's default certificate for this validator only.
   *
   * @param publicCert The public certificate to use for this validator
   * @returns A new, single-use XmlValidator instance
   */
  createValidator(publicCert: crypto.KeyLike): XmlValidator;

  createValidator(publicCert?: crypto.KeyLike): XmlValidator {
    if (publicCert) {
      if ("getCertFromKeyInfo" in this.options) {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { getCertFromKeyInfo: _getCertFromKeyInfo, ...rest } = this
          .options as KeyInfoXmlValidatorOptions;
        return new XmlValidator({ ...rest, publicCert });
      } else {
        return new XmlValidator({ ...this.options, publicCert });
      }
    }

    return new XmlValidator(this.options);
  }
}
