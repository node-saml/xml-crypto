import {
  CanonicalizationAlgorithmType,
  ComputeSignatureOptions,
  ComputeSignatureOptionsLocation,
  IdAttributeType,
  SignatureAlgorithmType,
} from "./types";
import { SignedXml } from "./signed-xml";
import * as crypto from "crypto";
import { buildIdXPathWithNamespaces } from "./utils";

const DEFAULT_ID_ATTRIBUTE_QNAMES = ["Id", "ID", "id"];

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
  getContent: (args?: { prefix?: string | null }) => string | null;

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
  uri?: undefined;
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
  xpath?: undefined;
}

/**
 * Reference configuration for signing operations.
 * Contains only the inputs needed to create a signature reference.
 */
export type SigningReference = XPathSigningReference | UriSigningReference;

/**
 * Configuration options for XML-DSig signing.
 */
export interface XmlDSigSignerOptions {
  /**
   * Names of XML attributes to treat as element identifiers.
   * Used when resolving URI references in signatures.
   * @default ["Id", "ID", "id"]
   * @example For WS-Security: [{ prefix: "wsu", localName: "Id", namespaceUri: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" }]
   */
  idAttributes?: IdAttributeType[];

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
}

/**
 * Result of a signing operation.
 */
export interface SigningResult {
  /** The complete signed XML document */
  signedDocument: string;

  /** The signature XML fragment only */
  signatureXml: string;
}

/**
 * A focused API for XML signing operations with enhanced security.
 * This class can be instantiated once and reused multiple times to sign different documents.
 */
export class XmlDSigSigner {
  private readonly options: XmlDSigSignerOptions & { idAttributes: IdAttributeType[] };
  private readonly computeOptions: ComputeSignatureOptions;

  /**
   * Creates a new XmlDSigSigner instance.
   *
   * @param options Configuration options for signing
   */
  constructor(options: XmlDSigSignerOptions) {
    if (!options.signatureAlgorithm) {
      throw new Error("signatureAlgorithm is required for XmlDSigSigner");
    }

    if (!options.canonicalizationAlgorithm) {
      throw new Error("canonicalizationAlgorithm is required for XmlDSigSigner");
    }

    this.options = {
      ...options,
      idAttributes:
        Array.isArray(options.idAttributes) && options.idAttributes.length > 0
          ? options.idAttributes
          : DEFAULT_ID_ATTRIBUTE_QNAMES,
    };

    // Prepare compute options
    this.computeOptions = {
      prefix: this.options.prefix,
      attrs: this.options.attributes,
      location: this.options.location,
      existingPrefixes: this.options.existingPrefixes,
    };
  }

  /**
   * Signs the XML document.
   *
   * @param xml The XML document to sign
   * @param privateKey The private key to use for signing
   * @param references Array of references to sign (required)
   * @returns The signing result with signed document and signature XML
   */
  sign(xml: string, privateKey: crypto.KeyLike, references: SigningReference[]): SigningResult {
    if (!references || references.length === 0) {
      throw new Error("At least one reference is required for signing");
    }

    // Create a fresh SignedXml instance for this signing operation
    const signedXml = this.createSignedXml(privateKey);

    // Add all references
    for (const reference of references) {
      this.addSigningReference(signedXml, reference);
    }

    // Sign the document
    signedXml.computeSignature(xml, this.computeOptions);

    return {
      signedDocument: signedXml.getSignedXml(),
      signatureXml: signedXml.getSignatureXml(),
    };
  }

  /**
   * Adds a reference to be signed.
   *
   * @param signedXml The SignedXml instance
   * @param reference The reference configuration
   */
  private addSigningReference(signedXml: SignedXml, reference: SigningReference): void {
    // Validate that URI is not in attributes
    if (reference.attributes && "URI" in reference.attributes) {
      throw new Error("URI must be specified on the reference configuration, not in attributes");
    }

    // Convert SigningReference to the format expected by SignedXml
    if ("xpath" in reference && reference.xpath !== undefined) {
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
    } else if ("uri" in reference && reference.uri !== undefined) {
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
        xpath = buildIdXPathWithNamespaces(this.options.idAttributes, id);
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
    } else {
      throw new Error("SigningReference must have either 'xpath' or 'uri' defined");
    }
  }

  private createSignedXml(privateKey: crypto.KeyLike): SignedXml {
    // Handle KeyInfo configuration
    let getKeyInfoContent: ((args?: { prefix?: string | null }) => string | null) | undefined;
    let keyInfoAttributes: Record<string, string> | undefined;

    if (this.options.keyInfo) {
      getKeyInfoContent = this.options.keyInfo.getContent;

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

    return new SignedXml({
      privateKey,
      signatureAlgorithm: this.options.signatureAlgorithm,
      canonicalizationAlgorithm: this.options.canonicalizationAlgorithm,
      inclusiveNamespacesPrefixList: this.options.inclusiveNamespacesPrefixList,
      keyInfoAttributes: keyInfoAttributes,
      getKeyInfoContent: getKeyInfoContent,
      objects: this.options.objects,
      idAttributes: this.options.idAttributes,
    });
  }
}
