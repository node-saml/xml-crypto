import {
  CanonicalizationAlgorithmType,
  ComputeSignatureOptions,
  ComputeSignatureOptionsLocation,
  ErrorFirstCallback,
  SignatureAlgorithmType,
} from "./types";
import { SignedXml } from "./signed-xml";
import * as crypto from "crypto";
import { buildIdXPath } from "./utils";

const DEFAULT_ID_ATTRIBUTES = ["Id", "ID", "id"];

/**
 * Signature attributes as defined in XMLDSig spec and are emitted verbatim
 * @see https://www.w3.org/TR/xmldsig-core/#sec-Signature
 */
export type SignatureAttributes = {
  /** Optional ID attribute */
  Id?: string;
} & {
  /** Any additional custom attributes (must be in a different namespace) */
  [key: string]: string;
};

/**
 * KeyInfo attributes as defined in XMLDSig spec and are emitted verbatim
 * @see https://www.w3.org/TR/xmldsig-core/#sec-KeyInfo
 */
export type KeyInfoAttributes = {
  /** Optional ID attribute */
  Id?: string;
} & {
  /** Any additional custom attributes (must be in a different namespace) */
  [key: string]: string;
};

/**
 * Reference attributes as defined in XMLDSig spec and are emitted verbatim
 * @see https://www.w3.org/TR/xmldsig-core1/#sec-Reference
 */
export type ReferenceAttributes = {
  /** Optional ID attribute */
  Id?: string;
  /** Optional Type attribute */
  Type?: string;
} & {
  /** Custom attributes currently not supported by SignedXml */
};

/**
 * Configuration for KeyInfo element in XML signatures.
 */
export interface KeyInfoConfig {
  /**
   * Function to generate custom content for the KeyInfo element.
   * This function receives the current prefix context and should return the complete XML content
   * that will be placed inside the KeyInfo element.
   *
   * @param args - Object containing the current prefix being used for the signature
   * @returns The KeyInfo content as a string, or null to omit KeyInfo
   *
   * @example
   * ```typescript
   * content: ({ prefix }) => {
   *   const ns = prefix ? `${prefix}:` : '';
   *   return `<${ns}X509Data><${ns}X509Certificate>...</${ns}X509Certificate></${ns}X509Data>`;
   * }
   * ```
   */
  content: (args?: { prefix?: string | null }) => string | null;

  /** Attributes to add to the KeyInfo element */
  attributes?: KeyInfoAttributes;
}

/**
 * Object attributes as defined in XMLDSig spec and are emitted verbatim
 * @see https://www.w3.org/TR/xmldsig-core/#sec-Object
 */
export type ObjectAttributes = {
  /** Optional ID attribute */
  Id?: string;
  /** Optional MIME type attribute */
  MimeType?: string;
  /** Optional encoding attribute */
  Encoding?: string;
} & {
  /** Any additional custom attributes (must be in a different namespace) */
  [key: string]: string | undefined;
};

/**
 * Configuration for Object elements in XML signatures.
 */
export interface ObjectConfig {
  /** The content to include in the Object element */
  content: string;

  /** Attributes to add to the Object element */
  attributes?: ObjectAttributes;
}

/**
 * Base interface for signing reference configuration.
 */
interface BaseSigningReference {
  // An array of transforms to be applied to the data before signing.
  transforms: ReadonlyArray<string>;

  // The algorithm used to calculate the digest value of the data.
  digestAlgorithm: string;

  // A list of namespace prefixes to be treated as "inclusive" during canonicalization.
  inclusiveNamespacesPrefixList?: string[];

  // Attributes to add to the Reference element
  attributes?: ReferenceAttributes;
}

/**
 * Reference configuration for signing operations using XPath selection.
 * Use this when you want to sign specific elements selected by an XPath expression.
 */
export interface XPathSigningReference extends BaseSigningReference {
  // The XPath expression that selects the data to be signed.
  xpath: string;
}

/**
 * Reference configuration for signing operations using URI.
 * Use this when you want to sign data identified by a specific URI.
 * Use uri: "" to sign the entire document (enveloped signature).
 */
export interface UriSigningReference extends BaseSigningReference {
  // The URI that identifies the data to be signed.
  // Use "" for enveloped signatures (signs the entire document).
  uri: string;
}

/**
 * Reference configuration for signing operations.
 * Contains only the inputs needed to create a signature reference.
 */
export type SigningReference = XPathSigningReference | UriSigningReference;

/**
 * Base interface for signing factory options.
 */
interface BaseXmlSignerFactoryOptionsCommon {
  /** You can provide a default private key here, which will be used by all signers created by the factory. */
  privateKey?: crypto.KeyLike;

  /** Use a custom prefix for the xmldsig namespace */
  prefix?: string;

  /** A hash of attributes and values to add to the signature root node */
  attributes?: SignatureAttributes;

  /** Location configuration for where to place the signature */
  location?: ComputeSignatureOptionsLocation;

  /** A hash of prefixes and namespaces already in the xml */
  existingPrefixes?: Record<string, string>;

  /** The signature algorithm to use (required) */
  signatureAlgorithm: SignatureAlgorithmType;

  /** The canonicalization algorithm to use (required) */
  canonicalizationAlgorithm: CanonicalizationAlgorithmType;

  /** Namespace prefixes for inclusive canonicalization */
  inclusiveNamespacesPrefixList?: string | string[];

  /**
   * Configuration for the KeyInfo element.
   * This is the recommended way to include certificate information in signatures.
   */
  keyInfo?: KeyInfoConfig;

  /** Object elements to include in the signature */
  objects?: ObjectConfig[];

  /** You can add references here to have them included by default in every signer created by the factory */
  references?: SigningReference[];
}

/**
 * When WSSecurity mode is disabled, users can specify custom ID attributes.
 */
export interface BaseXmlSignerFactoryOptionsWithId extends BaseXmlSignerFactoryOptionsCommon {
  /**
   * Enable WS-Security mode for ID handling.
   * When true, creates/validates IDs with the WS-Security namespace.
   * @default false
   */
  enableWSSecurityMode?: false;

  /** Custom ID attributes to use for element identification */
  idAttributes?: string[];
}

/**
 * When WSSecurity mode is enabled, ID attributes are fixed to WS-Security standards. (wsu:Id)
 * Accepting idAttributes in this mode is disallowed to prevent confusion.
 */
export interface BaseXmlSignerFactoryOptionsWS extends BaseXmlSignerFactoryOptionsCommon {
  /**
   * Enable WS-Security mode for ID handling.
   * When true, creates/validates IDs with the WS-Security namespace.
   * @default false
   */
  enableWSSecurityMode: true;

  /** ID attributes are not configurable in WS-Security mode */
  idAttributes?: never;
}

/**
 * Options for the XmlSigner constructor.
 */
export type XmlSignerFactoryOptions =
  | BaseXmlSignerFactoryOptionsWithId
  | BaseXmlSignerFactoryOptionsWS;

/**
 * Adds a reference to be signed.
 *
 * @param signedXml The SignedXml instance
 * @param reference The reference configuration
 */
function addSigningReference(signedXml: SignedXml, reference: SigningReference): void {
  // Validate that URI is not in attributes
  if (reference.attributes && "URI" in reference.attributes) {
    throw new Error("URI must be specified on the reference configuration, not in attributes");
  }

  // Convert SigningReference to the format expected by SignedXml
  if ("xpath" in reference) {
    // XPath-based reference
    signedXml.addReference({
      xpath: reference.xpath,
      transforms: reference.transforms,
      digestAlgorithm: reference.digestAlgorithm,
      inclusiveNamespacesPrefixList: reference.inclusiveNamespacesPrefixList || [],
      isEmptyUri: false,
      id: reference.attributes?.Id,
      type: reference.attributes?.Type,
      uri: undefined,
    });
  } else {
    // URI-based reference - convert URI to XPath
    let xpath: string;
    let isEmptyUri: boolean;

    if (reference.uri === "") {
      // Empty URI means sign the entire document (enveloped signature)
      xpath = "/*";
      isEmptyUri = true;
    } else if (reference.uri.startsWith("#")) {
      // Fragment identifier - select element with matching ID
      const id = reference.uri.substring(1);
      // Build a safe XPath literal that handles quotes correctly
      xpath = buildIdXPath(signedXml.idAttributes, id);
      isEmptyUri = false;
    } else {
      // External URI - this is not supported for signing as we can only sign content within the document
      throw new Error(`External URI references are not supported for signing: ${reference.uri}`);
    }

    signedXml.addReference({
      xpath: xpath,
      transforms: reference.transforms,
      digestAlgorithm: reference.digestAlgorithm,
      inclusiveNamespacesPrefixList: reference.inclusiveNamespacesPrefixList || [],
      isEmptyUri: isEmptyUri,
      id: reference.attributes?.Id,
      type: reference.attributes?.Type,
      uri: reference.uri,
    });
  }
}

/**
 * A focused API for XML signing operations.
 * Provides a safer, more intuitive interface compared to the general-purpose SignedXml class.
 */
export class XmlSigner {
  private readonly signedXml: SignedXml;
  private readonly computeOptions: ComputeSignatureOptions;
  private hasBeenSigned: boolean = false;

  /**
   * Creates a new XmlSigner instance. It is recommended to use XmlSignerFactory to create instances of this class.
   *
   * @param signedXml Pre-configured SignedXml instance
   * @param computeOptions Options passed to SignedXml.computeSignature
   */
  constructor(signedXml: SignedXml, computeOptions: ComputeSignatureOptions) {
    this.signedXml = signedXml;
    this.computeOptions = computeOptions;
  }

  public addReference(reference: SigningReference): void {
    if (this.hasBeenSigned) {
      throw new Error(
        "Cannot add references after signing has been performed. Create a new XmlSigner instance to add more references.",
      );
    }
    addSigningReference(this.signedXml, reference);
  }

  /**
   * Signs the XML document synchronously.
   *
   * @param xml The XML document to sign
   * @returns The signed XML document
   */
  sign(xml: string): string;

  /**
   * Signs the XML document asynchronously.
   *
   * @param xml The XML document to sign
   * @param callback Callback function to handle the result
   */
  sign(xml: string, callback: ErrorFirstCallback<string>): void;

  sign(xml: string, callback?: ErrorFirstCallback<string>): string | void {
    if (this.hasBeenSigned) {
      throw new Error(
        "This XmlSigner instance has already been used to sign a document. Create a new instance to sign another document.",
      );
    }

    if (callback) {
      try {
        this.signedXml.computeSignature(xml, this.computeOptions, (err, signedXmlInstance) => {
          if (err) {
            callback(err);
          } else if (signedXmlInstance) {
            this.hasBeenSigned = true;
            callback(null, signedXmlInstance.getSignedXml());
          } else {
            callback(new Error("Signing failed: no signed XML instance returned"));
          }
        });
      } catch (error) {
        callback(error instanceof Error ? error : new Error("Unknown signing error"));
      }
    } else {
      this.signedXml.computeSignature(xml, this.computeOptions);
      this.hasBeenSigned = true;
      return this.signedXml.getSignedXml();
    }
  }

  /**
   * Gets the signature XML fragment.
   * Must be called after signing.
   *
   * @returns The signature XML
   */
  getSignatureXml(): string {
    if (!this.hasBeenSigned) {
      throw new Error("Cannot get signature XML before signing a document. Call sign() first.");
    }
    return this.signedXml.getSignatureXml();
  }
}

/**
 * Factory for creating XmlSigner instances with consistent configuration.
 * This provides a clean separation between configuration and the signing process.
 */
export class XmlSignerFactory {
  private readonly options: XmlSignerFactoryOptions;

  /**
   * Creates a new XmlSignerFactory instance.
   *
   * @param options Configuration options for the factory
   */
  constructor(options: XmlSignerFactoryOptions) {
    if (!options.signatureAlgorithm) {
      throw new Error("signatureAlgorithm is required for XmlSignerFactory");
    }

    if (!options.canonicalizationAlgorithm) {
      throw new Error("canonicalizationAlgorithm is required for XmlSignerFactory");
    }

    this.options = { ...options };
  }

  /**
   * Creates a new XmlSigner instance;
   *
   * @returns A new XmlSigner instance
   */
  createSigner(): XmlSigner;

  /**
   * Creates a new XmlSigner instance with the provided private key.
   *
   * @param privateKey The private key to use for signing
   * @returns A new XmlSigner instance
   */
  createSigner(privateKey: crypto.KeyLike): XmlSigner;

  /**
   * Creates a new XmlSigner instance with the provided private key.
   *
   * @param privateKey The private key to use for signing
   * @returns A new XmlSigner instance
   */
  createSigner(privateKey?: crypto.KeyLike): XmlSigner {
    if (!privateKey) {
      if (!this.options.privateKey) {
        throw new Error("privateKey is required to create an XmlSigner");
      } else {
        privateKey = this.options.privateKey;
      }
    }

    // Handle KeyInfo configuration
    let getKeyInfoContent: ((args?: { prefix?: string | null }) => string | null) | undefined;
    let keyInfoAttributes: Record<string, string> | undefined;

    if (this.options.keyInfo) {
      getKeyInfoContent = this.options.keyInfo.content;

      // Filter out undefined values from attributes
      if (this.options.keyInfo.attributes) {
        const filteredAttrs: Record<string, string> = {};
        for (const [key, value] of Object.entries(this.options.keyInfo.attributes)) {
          if (value !== undefined) {
            filteredAttrs[key] = value;
          }
        }
        keyInfoAttributes = Object.keys(filteredAttrs).length > 0 ? filteredAttrs : undefined;
      }
    }

    const signedXml = new SignedXml({
      privateKey,
      signatureAlgorithm: this.options.signatureAlgorithm,
      canonicalizationAlgorithm: this.options.canonicalizationAlgorithm,
      inclusiveNamespacesPrefixList: this.options.inclusiveNamespacesPrefixList,
      keyInfoAttributes: keyInfoAttributes,
      getKeyInfoContent: getKeyInfoContent,
      objects: this.options.objects,
      idMode: this.options.enableWSSecurityMode ? "wssecurity" : undefined,
    });

    // Force the SignedXml to use the appropriate ID attributes
    signedXml.idAttributes = this.options.enableWSSecurityMode
      ? ["Id"]
      : this.options.idAttributes && this.options.idAttributes.length > 0
        ? this.options.idAttributes
        : DEFAULT_ID_ATTRIBUTES;

    if (this.options.references) {
      for (const reference of this.options.references) {
        addSigningReference(signedXml, reference);
      }
    }

    return new XmlSigner(signedXml, {
      prefix: this.options.prefix,
      attrs: this.options.attributes,
      location: this.options.location,
      existingPrefixes: this.options.existingPrefixes,
    });
  }
}
