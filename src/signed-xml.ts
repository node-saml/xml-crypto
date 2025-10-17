import type {
  CanonicalizationAlgorithmType,
  CanonicalizationOrTransformAlgorithmType,
  CanonicalizationOrTransformationAlgorithm,
  CanonicalizationOrTransformationAlgorithmProcessOptions,
  ComputeSignatureOptions,
  ErrorFirstCallback,
  GetKeyInfoContentArgs,
  HashAlgorithm,
  HashAlgorithmType,
  KeyLike,
  Reference,
  SignatureAlgorithm,
  SignatureAlgorithmType,
  SignedXmlOptions,
} from "./types";

import * as isDomNode from "@xmldom/is-dom-node";
import * as xmldom from "@xmldom/xmldom";
import { deprecate } from "util";
import * as xpath from "xpath";
import * as c14n from "./c14n-canonicalization";
import * as envelopedSignatures from "./enveloped-signature";
import * as execC14n from "./exclusive-canonicalization";
import * as hashAlgorithms from "./hash-algorithms";
import * as signatureAlgorithms from "./signature-algorithms";
import * as utils from "./utils";

/**
 * Result type for signature preparation containing all DOM nodes needed for finalization
 */
interface SignaturePreparationResult {
  doc: Document;
  prefix: string | undefined;
  signatureDoc: Node;
  signedInfoNode: Node;
}

export class SignedXml {
  idMode?: "wssecurity";
  idAttributes: string[];
  /**
   * A {@link Buffer} or pem encoded {@link String} containing your private key
   */
  privateKey?: KeyLike;
  publicCert?: KeyLike;
  /**
   * One of the supported signature algorithms.
   * @see {@link SignatureAlgorithmType}
   */
  signatureAlgorithm?: SignatureAlgorithmType = undefined;
  /**
   * Rules used to convert an XML document into its canonical form.
   */
  canonicalizationAlgorithm?: CanonicalizationAlgorithmType = undefined;
  /**
   * It specifies a list of namespace prefixes that should be considered "inclusive" during the canonicalization process.
   */
  inclusiveNamespacesPrefixList: string[] = [];
  namespaceResolver: XPathNSResolver = {
    lookupNamespaceURI: function (/* prefix */) {
      throw new Error("Not implemented");
    },
  };
  implicitTransforms: ReadonlyArray<CanonicalizationOrTransformAlgorithmType> = [];
  keyInfoAttributes: { [attrName: string]: string } = {};
  getKeyInfoContent = SignedXml.getKeyInfoContent;
  getCertFromKeyInfo = SignedXml.getCertFromKeyInfo;

  // Internal state
  private id = 0;
  private signedXml: string | undefined = undefined;
  private signatureXml = "";
  private signatureNode: Node | null = null;
  private signatureValue = "";
  private originalXmlWithIds = "";
  private keyInfo: Node | null = null;
  private signatureLoadedExplicitly = false;

  /**
   * Contains the references that were signed.
   * @see {@link Reference}
   */
  private references: Reference[] = [];

  /**
   * Contains the canonicalized XML of the references that were validly signed.
   *
   * This populates with the canonical XML of the reference only after
   * verifying the signature is cryptographically authentic.
   */
  private signedReferences: string[] = [];

  /**
   *  To add a new transformation algorithm create a new class that implements the {@link TransformationAlgorithm} interface, and register it here. More info: {@link https://github.com/node-saml/xml-crypto#customizing-algorithms|Customizing Algorithms}
   */
  CanonicalizationAlgorithms: Record<
    CanonicalizationOrTransformAlgorithmType,
    new () => CanonicalizationOrTransformationAlgorithm
  > = {
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315": c14n.C14nCanonicalization,
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments":
      c14n.C14nCanonicalizationWithComments,
    "http://www.w3.org/2001/10/xml-exc-c14n#": execC14n.ExclusiveCanonicalization,
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments":
      execC14n.ExclusiveCanonicalizationWithComments,
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature": envelopedSignatures.EnvelopedSignature,
  };

  // TODO: In v7.x we may consider deprecating sha1

  /**
   * To add a new hash algorithm create a new class that implements the {@link HashAlgorithm} interface, and register it here. More info: {@link https://github.com/node-saml/xml-crypto#customizing-algorithms|Customizing Algorithms}
   */
  HashAlgorithms: Record<HashAlgorithmType, new () => HashAlgorithm> = {
    "http://www.w3.org/2000/09/xmldsig#sha1": hashAlgorithms.Sha1,
    "http://www.w3.org/2001/04/xmlenc#sha256": hashAlgorithms.Sha256,
    "http://www.w3.org/2001/04/xmlenc#sha512": hashAlgorithms.Sha512,
  };

  // TODO: In v7.x we may consider deprecating sha1

  /**
   * To add a new signature algorithm create a new class that implements the {@link SignatureAlgorithm} interface, and register it here. More info: {@link https://github.com/node-saml/xml-crypto#customizing-algorithms|Customizing Algorithms}
   */
  SignatureAlgorithms: Record<SignatureAlgorithmType, new () => SignatureAlgorithm> = {
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1": signatureAlgorithms.RsaSha1,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": signatureAlgorithms.RsaSha256,
    "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1": signatureAlgorithms.RsaSha256Mgf1,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": signatureAlgorithms.RsaSha512,
    // Disabled by default due to key confusion concerns.
    // 'http://www.w3.org/2000/09/xmldsig#hmac-sha1': SignatureAlgorithms.HmacSha1
  };

  static defaultNsForPrefix = {
    ds: "http://www.w3.org/2000/09/xmldsig#",
  };

  static noop = () => null;

  /**
   * The SignedXml constructor provides an abstraction for sign and verify xml documents. The object is constructed using
   * @param options {@link SignedXmlOptions}
   */
  constructor(options: SignedXmlOptions = {}) {
    const {
      idMode,
      idAttribute,
      privateKey,
      publicCert,
      signatureAlgorithm,
      canonicalizationAlgorithm,
      inclusiveNamespacesPrefixList,
      implicitTransforms,
      keyInfoAttributes,
      getKeyInfoContent,
      getCertFromKeyInfo,
    } = options;

    // Options
    this.idMode = idMode;
    this.idAttributes = ["Id", "ID", "id"];
    if (idAttribute) {
      this.idAttributes.unshift(idAttribute);
    }
    this.privateKey = privateKey;
    this.publicCert = publicCert;
    this.signatureAlgorithm = signatureAlgorithm ?? this.signatureAlgorithm;
    this.canonicalizationAlgorithm = canonicalizationAlgorithm;
    if (typeof inclusiveNamespacesPrefixList === "string") {
      this.inclusiveNamespacesPrefixList = inclusiveNamespacesPrefixList.split(" ");
    } else if (utils.isArrayHasLength(inclusiveNamespacesPrefixList)) {
      this.inclusiveNamespacesPrefixList = inclusiveNamespacesPrefixList;
    }
    this.implicitTransforms = implicitTransforms ?? this.implicitTransforms;
    this.keyInfoAttributes = keyInfoAttributes ?? this.keyInfoAttributes;
    this.getKeyInfoContent = getKeyInfoContent ?? this.getKeyInfoContent;
    this.getCertFromKeyInfo = getCertFromKeyInfo ?? this.getCertFromKeyInfo;
    this.CanonicalizationAlgorithms;
    this.HashAlgorithms;
    this.SignatureAlgorithms;
  }

  /**
   * Due to key-confusion issues, it's risky to have both hmac
   * and digital signature algorithms enabled at the same time.
   * This enables HMAC and disables other signing algorithms.
   */
  enableHMAC(): void {
    this.SignatureAlgorithms = {
      "http://www.w3.org/2000/09/xmldsig#hmac-sha1": signatureAlgorithms.HmacSha1,
    };
    this.getKeyInfoContent = SignedXml.noop;
  }

  /**
   * Builds the contents of a KeyInfo element as an XML string.
   *
   * For example, if the value of the prefix argument is 'foo', then
   * the resultant XML string will be "<foo:X509Data></foo:X509Data>"
   *
   * @return an XML string representation of the contents of a KeyInfo element, or `null` if no `KeyInfo` element should be included
   */
  static getKeyInfoContent({ publicCert, prefix }: GetKeyInfoContentArgs): string | null {
    if (publicCert == null) {
      return null;
    }

    prefix = prefix ? `${prefix}:` : "";

    let x509Certs = "";
    if (Buffer.isBuffer(publicCert)) {
      publicCert = publicCert.toString("latin1");
    }

    let publicCertMatches: string[] = [];
    if (typeof publicCert === "string") {
      publicCertMatches = publicCert.match(utils.EXTRACT_X509_CERTS) || [];
    }

    if (publicCertMatches.length > 0) {
      x509Certs = publicCertMatches
        .map(
          (c) =>
            `<${prefix}X509Certificate>${utils
              .pemToDer(c)
              .toString("base64")}</${prefix}X509Certificate>`,
        )
        .join("");
    }

    return `<${prefix}X509Data>${x509Certs}</${prefix}X509Data>`;
  }

  /**
   * Returns the value of the signing certificate based on the contents of the
   * specified KeyInfo.
   *
   * @param keyInfo KeyInfo element (@see https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-X509Data)
   * @return the signing certificate as a string in PEM format
   */
  static getCertFromKeyInfo(keyInfo?: Node | null): string | null {
    if (keyInfo != null) {
      const cert = xpath.select1(".//*[local-name(.)='X509Certificate']", keyInfo);
      if (isDomNode.isNodeLike(cert)) {
        return utils.derToPem(cert.textContent ?? "", "CERTIFICATE");
      }
    }

    return null;
  }

  /**
   * Validates the signature of the provided XML document synchronously using the configured key info provider.
   *
   * @param xml The XML document containing the signature to be validated.
   * @returns `true` if the signature is valid
   * @throws Error if no key info resolver is provided.
   */
  checkSignature(xml: string): boolean;
  /**
   * Validates the signature of the provided XML document synchronously using the configured key info provider.
   *
   * @param xml The XML document containing the signature to be validated.
   * @param callback Callback function to handle the validation result asynchronously.
   * @throws Error if the last parameter is provided and is not a function, or if no key info resolver is provided.
   */
  checkSignature(xml: string, callback: (error: Error | null, isValid?: boolean) => void): void;
  checkSignature(
    xml: string,
    callback?: (error: Error | null, isValid?: boolean) => void,
  ): unknown {
    if (callback != null && typeof callback !== "function") {
      throw new Error("Last parameter must be a callback function");
    }

    const doc = new xmldom.DOMParser().parseFromString(xml);

    // Security: Prevent cross-document signature reuse attacks while supporting
    // legitimate use of loadSignature() for detached signatures and documents with
    // multiple signatures.
    //
    // Strategy:
    // 1. Always scan the current document for embedded signatures
    // 2. If no embedded signature is found AND no signature was explicitly loaded,
    //    reject immediately (unsigned document)
    // 3. If signature was explicitly loaded and this is the FIRST validation,
    //    allow using the preloaded signature (supports detached signatures)
    // 4. If the XML has changed since last validation, reject reusing old signature
    //    and require reloading from current document

    const signatures = this.findSignatures(doc);
    const hasValidatedBefore = this.signedXml !== undefined;
    const xmlChanged = hasValidatedBefore && this.signedXml !== xml;

    // If no signature in current document and none was preloaded, reject immediately
    if (signatures.length === 0 && !this.signatureNode) {
      const error = new Error("No signature found in the document");
      if (callback) {
        callback(error, false);
        return;
      }
      throw error;
    }

    // Security: If we're validating for the first time after loadSignature() was called,
    // and the current document has NO embedded signatures, we need to determine if this
    // is a legitimate detached signature scenario or an attack.
    //
    // A detached signature is legitimate when the signature was loaded as a STANDALONE
    // XML string (via loadSignature(string)). If loadSignature was called with a node
    // extracted from a different document, we should reject.
    //
    // We detect detached signatures by checking if the signatureNode's root document
    // contains only the signature (i.e., it's a standalone signature document).
    if (!hasValidatedBefore && signatures.length === 0 && this.signatureNode) {
      // Check if this is a detached signature (signature is the root element of its document)
      // When loadSignature is called with a string, it creates a new Document where the
      // Signature is the documentElement.
      const signatureDoc = this.signatureNode.ownerDocument;
      const isStandaloneSignatureDoc =
        signatureDoc &&
        signatureDoc.documentElement &&
        signatureDoc.documentElement.localName === "Signature" &&
        signatureDoc.documentElement.namespaceURI === "http://www.w3.org/2000/09/xmldsig#";

      if (!isStandaloneSignatureDoc) {
        // Signature was loaded from within another document, not as a detached signature
        // Reject to prevent: loadSignature(sigFromDocA) -> checkSignature(unsignedDocB)
        const error = new Error("No signature found in the document");
        if (callback) {
          callback(error, false);
          return;
        }
        throw error;
      }
    }

    // If XML changed from previous validation, we must reload from current document
    // This prevents: checkSignature(docA) -> checkSignature(docB) reusing docA's signature
    if (xmlChanged && signatures.length === 0) {
      const error = new Error("No signature found in the document");
      if (callback) {
        callback(error, false);
        return;
      }
      throw error;
    }

    // Determine if we should reload signature from current document
    // Reload if: no signature loaded, XML changed, or signature was previously auto-loaded
    // Keep preloaded signature only if it was explicitly loaded and this is first validation
    const shouldReloadSignature =
      !this.signatureNode ||
      (xmlChanged && signatures.length > 0) ||
      (!this.signatureLoadedExplicitly && hasValidatedBefore);

    if (shouldReloadSignature) {
      if (signatures.length === 0) {
        const error = new Error("No signature found in the document");
        if (callback) {
          callback(error, false);
          return;
        }
        throw error;
      }
      if (signatures.length > 1) {
        const error = new Error(
          "Multiple signatures found. Use loadSignature() to specify which signature to validate",
        );
        if (callback) {
          callback(error, false);
          return;
        }
        throw error;
      }
      this.loadSignature(signatures[0]);
      // Mark that this was auto-loaded, not explicitly loaded
      this.signatureLoadedExplicitly = false;
    }

    this.signedXml = xml;

    // Reset the references as only references from our re-parsed signedInfo node can be trusted
    this.references = [];

    const unverifiedSignedInfoCanon = this.getCanonSignedInfoXml(doc);
    if (!unverifiedSignedInfoCanon) {
      if (callback) {
        callback(new Error("Canonical signed info cannot be empty"), false);
        return;
      }

      throw new Error("Canonical signed info cannot be empty");
    }

    // unsigned, verify later to keep with consistent callback behavior
    const parsedUnverifiedSignedInfo = new xmldom.DOMParser().parseFromString(
      unverifiedSignedInfoCanon,
      "text/xml",
    );

    const unverifiedSignedInfoDoc = parsedUnverifiedSignedInfo.documentElement;
    if (!unverifiedSignedInfoDoc) {
      if (callback) {
        callback(new Error("Could not parse unverifiedSignedInfoCanon into a document"), false);
        return;
      }

      throw new Error("Could not parse unverifiedSignedInfoCanon into a document");
    }

    const references = utils.findChildren(unverifiedSignedInfoDoc, "Reference");
    if (!utils.isArrayHasLength(references)) {
      if (callback) {
        callback(new Error("could not find any Reference elements"), false);
        return;
      }

      throw new Error("could not find any Reference elements");
    }

    // TODO: In a future release we'd like to load the Signature and its References at the same time,
    // however, in the `.loadSignature()` method we don't have the entire document,
    // which we need to to keep the inclusive namespaces
    for (const reference of references) {
      this.loadReference(reference);
    }

    /* eslint-disable-next-line deprecation/deprecation */
    if (!this.getReferences().every((ref) => this.validateReference(ref, doc))) {
      /* Trustworthiness can only be determined if SignedInfo's (which holds References' DigestValue(s)
         which were validated at this stage) signature is valid. Execution does not proceed to validate
         signature phase thus each References' DigestValue must be considered to be untrusted (attacker
         might have injected any data with new new references and/or recalculated new DigestValue for
         altered Reference(s)). Returning any content via `signedReferences` would give false sense of
         trustworthiness if/when SignedInfo's (which holds references' DigestValues) signature is not
         valid(ated). Put simply: if one fails, they are all not trustworthy.
      */
      this.signedReferences = [];
      this.references.forEach((ref) => {
        ref.signedReference = undefined;
      });
      // TODO: add this breaking change here later on for even more security: `this.references = [];`

      if (callback) {
        callback(new Error("Could not validate all references"), false);
        return;
      }

      // We return false because some references validated, but not all
      // We should actually be throwing an error here, but that would be a breaking change
      // See https://www.w3.org/TR/xmldsig-core/#sec-CoreValidation
      return false;
    }

    // (Stage B authentication step, show that the `signedInfoCanon` is signed)

    // First find the key & signature algorithm, these should match
    // Stage B: Take the signature algorithm and key and verify the `SignatureValue` against the canonicalized `SignedInfo`
    const signer = this.findSignatureAlgorithm(this.signatureAlgorithm);
    const key = this.getCertFromKeyInfo(this.keyInfo) || this.publicCert || this.privateKey;
    if (key == null) {
      throw new Error("KeyInfo or publicCert or privateKey is required to validate signature");
    }

    // Check the signature verification to know whether to reset signature value or not.
    const sigRes = signer.verifySignature(unverifiedSignedInfoCanon, key, this.signatureValue);

    // Detect if the verifySignature method returned a Promise (async algorithm)
    if (sigRes instanceof Promise) {
      throw new Error(
        "Async algorithms cannot be used with synchronous methods. Use checkSignatureAsync() instead.",
      );
    }

    if (sigRes === true) {
      if (callback) {
        callback(null, true);
      } else {
        return true;
      }
    } else {
      // Ideally, we would start by verifying the `signedInfoCanon` first,
      // but that may cause some breaking changes, so we'll handle that in v7.x.
      // If we were validating `signedInfoCanon` first, we wouldn't have to reset this array.
      this.signedReferences = [];
      this.references.forEach((ref) => {
        ref.signedReference = undefined;
      });
      // TODO: add this breaking change here later on for even more security: `this.references = [];`

      if (callback) {
        callback(
          new Error(`invalid signature: the signature value ${this.signatureValue} is incorrect`),
          false,
        );
        return; // return early
      } else {
        throw new Error(
          `invalid signature: the signature value ${this.signatureValue} is incorrect`,
        );
      }
    }
  }

  /**
   * Validates the signature of the provided XML document asynchronously.
   * This method is designed to work with async algorithms (like WebCrypto).
   *
   * @param xml The XML document containing the signature to be validated.
   * @returns Promise<boolean> that resolves to true if the signature is valid
   * @throws Error if validation fails
   */
  async checkSignatureAsync(xml: string): Promise<boolean> {
    const doc = new xmldom.DOMParser().parseFromString(xml);

    // Security: Prevent cross-document signature reuse attacks while supporting
    // legitimate use of loadSignature() for detached signatures and documents with
    // multiple signatures.
    //
    // Strategy:
    // 1. Always scan the current document for embedded signatures
    // 2. If no embedded signature is found AND no signature was explicitly loaded,
    //    reject immediately (unsigned document)
    // 3. If signature was explicitly loaded and this is the FIRST validation,
    //    allow using the preloaded signature (supports detached signatures)
    // 4. If the XML has changed since last validation, reject reusing old signature
    //    and require reloading from current document

    const signatures = this.findSignatures(doc);
    const hasValidatedBefore = this.signedXml !== undefined;
    const xmlChanged = hasValidatedBefore && this.signedXml !== xml;

    // If no signature in current document and none was preloaded, reject immediately
    if (signatures.length === 0 && !this.signatureNode) {
      throw new Error("No signature found in the document");
    }

    // Security: If we're validating for the first time after loadSignature() was called,
    // and the current document has NO embedded signatures, we need to determine if this
    // is a legitimate detached signature scenario or an attack.
    //
    // A detached signature is legitimate when the signature was loaded as a STANDALONE
    // XML string (via loadSignature(string)). If loadSignature was called with a node
    // extracted from a different document, we should reject.
    //
    // We detect detached signatures by checking if the signatureNode's root document
    // contains only the signature (i.e., it's a standalone signature document).
    if (!hasValidatedBefore && signatures.length === 0 && this.signatureNode) {
      // Check if this is a detached signature (signature is the root element of its document)
      // When loadSignature is called with a string, it creates a new Document where the
      // Signature is the documentElement.
      const signatureDoc = this.signatureNode.ownerDocument;
      const isStandaloneSignatureDoc =
        signatureDoc &&
        signatureDoc.documentElement &&
        signatureDoc.documentElement.localName === "Signature" &&
        signatureDoc.documentElement.namespaceURI === "http://www.w3.org/2000/09/xmldsig#";

      if (!isStandaloneSignatureDoc) {
        // Signature was loaded from within another document, not as a detached signature
        // Reject to prevent: loadSignature(sigFromDocA) -> checkSignatureAsync(unsignedDocB)
        throw new Error("No signature found in the document");
      }
    }

    // If XML changed from previous validation, we must reload from current document
    // This prevents: checkSignature(docA) -> checkSignature(docB) reusing docA's signature
    if (xmlChanged && signatures.length === 0) {
      throw new Error("No signature found in the document");
    }

    // Determine if we should reload signature from current document
    // Reload if: no signature loaded, XML changed, or signature was previously auto-loaded
    // Keep preloaded signature only if it was explicitly loaded and this is first validation
    const shouldReloadSignature =
      !this.signatureNode ||
      (xmlChanged && signatures.length > 0) ||
      (!this.signatureLoadedExplicitly && hasValidatedBefore);

    if (shouldReloadSignature) {
      if (signatures.length === 0) {
        throw new Error("No signature found in the document");
      }
      if (signatures.length > 1) {
        throw new Error(
          "Multiple signatures found. Use loadSignature() to specify which signature to validate",
        );
      }
      this.loadSignature(signatures[0]);
      // Mark that this was auto-loaded, not explicitly loaded
      this.signatureLoadedExplicitly = false;
    }

    this.signedXml = xml;

    // Reset the references as only references from our re-parsed signedInfo node can be trusted
    this.references = [];

    const unverifiedSignedInfoCanon = this.getCanonSignedInfoXml(doc);
    if (!unverifiedSignedInfoCanon) {
      throw new Error("Canonical signed info cannot be empty");
    }

    const parsedUnverifiedSignedInfo = new xmldom.DOMParser().parseFromString(
      unverifiedSignedInfoCanon,
      "text/xml",
    );

    const unverifiedSignedInfoDoc = parsedUnverifiedSignedInfo.documentElement;
    if (!unverifiedSignedInfoDoc) {
      throw new Error("Could not parse unverifiedSignedInfoCanon into a document");
    }

    const references = utils.findChildren(unverifiedSignedInfoDoc, "Reference");
    if (!utils.isArrayHasLength(references)) {
      throw new Error("could not find any Reference elements");
    }

    for (const reference of references) {
      this.loadReference(reference);
    }

    // Validate all references asynchronously
    const validationResults = await Promise.all(
      /* eslint-disable-next-line deprecation/deprecation */
      this.getReferences().map((ref) => this.validateReferenceAsync(ref, doc)),
    );

    if (!validationResults.every((result) => result)) {
      this.signedReferences = [];
      this.references.forEach((ref) => {
        ref.signedReference = undefined;
      });
      throw new Error("Could not validate all references");
    }

    // Verify the signature
    const signer = this.findSignatureAlgorithm(this.signatureAlgorithm);
    const key = this.getCertFromKeyInfo(this.keyInfo) || this.publicCert || this.privateKey;
    if (key == null) {
      throw new Error("KeyInfo or publicCert or privateKey is required to validate signature");
    }

    const sigRes = await Promise.resolve(
      signer.verifySignature(unverifiedSignedInfoCanon, key, this.signatureValue),
    );

    if (sigRes === true) {
      return true;
    } else {
      this.signedReferences = [];
      this.references.forEach((ref) => {
        ref.signedReference = undefined;
      });
      throw new Error(`invalid signature: the signature value ${this.signatureValue} is incorrect`);
    }
  }

  private async validateReferenceAsync(ref: Reference, doc: Document): Promise<boolean> {
    const uri = ref.uri?.[0] === "#" ? ref.uri.substring(1) : ref.uri;
    let elem: xpath.SelectSingleReturnType = null;

    if (uri === "") {
      elem = xpath.select1("//*", doc);
    } else if (uri?.indexOf("'") !== -1) {
      throw new Error("Cannot validate a uri with quotes inside it");
    } else {
      let num_elements_for_id = 0;
      for (const attr of this.idAttributes) {
        const tmp_elemXpath = `//*[@*[local-name(.)='${attr}']='${uri}']`;
        const tmp_elem = xpath.select(tmp_elemXpath, doc);
        if (utils.isArrayHasLength(tmp_elem)) {
          num_elements_for_id += tmp_elem.length;

          if (num_elements_for_id > 1) {
            throw new Error(
              "Cannot validate a document which contains multiple elements with the " +
                "same value for the ID / Id / Id attributes, in order to prevent " +
                "signature wrapping attack.",
            );
          }

          elem = tmp_elem[0];
          ref.xpath = tmp_elemXpath;
        }
      }
    }

    if (!isDomNode.isNodeLike(elem)) {
      const validationError = new Error(
        `invalid signature: the signature references an element with uri ${ref.uri} but could not find such element in the xml`,
      );
      ref.validationError = validationError;
      return false;
    }

    const canonXml = this.getCanonReferenceXml(doc, ref, elem);
    const hash = this.findHashAlgorithm(ref.digestAlgorithm);
    const digest = await Promise.resolve(hash.getHash(canonXml));

    if (!utils.validateDigestValue(digest, ref.digestValue)) {
      const validationError = new Error(
        `invalid signature: for uri ${ref.uri} calculated digest is ${digest} but the xml to validate supplies digest ${ref.digestValue}`,
      );
      ref.validationError = validationError;
      return false;
    }

    this.signedReferences.push(canonXml);
    ref.signedReference = canonXml;

    return true;
  }

  private getCanonSignedInfoXml(doc: Document) {
    if (this.signatureNode == null) {
      throw new Error("No signature found.");
    }
    if (typeof this.canonicalizationAlgorithm !== "string") {
      throw new Error("Missing canonicalizationAlgorithm when trying to get signed info for XML");
    }

    const signedInfo = utils.findChildren(this.signatureNode, "SignedInfo");
    if (signedInfo.length === 0) {
      throw new Error("could not find SignedInfo element in the message");
    }
    if (signedInfo.length > 1) {
      throw new Error(
        "could not get canonicalized signed info for a signature that contains multiple SignedInfo nodes",
      );
    }

    if (
      this.canonicalizationAlgorithm === "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" ||
      this.canonicalizationAlgorithm ===
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
    ) {
      if (!doc || typeof doc !== "object") {
        throw new Error(
          "When canonicalization method is non-exclusive, whole xml dom must be provided as an argument",
        );
      }
    }

    /**
     * Search for ancestor namespaces before canonicalization.
     */
    const ancestorNamespaces = utils.findAncestorNs(doc, "//*[local-name()='SignedInfo']");

    const c14nOptions = {
      ancestorNamespaces: ancestorNamespaces,
    };

    return this.getCanonXml([this.canonicalizationAlgorithm], signedInfo[0], c14nOptions);
  }

  private getCanonReferenceXml(doc: Document, ref: Reference, node: Node) {
    /**
     * Search for ancestor namespaces before canonicalization.
     */
    if (Array.isArray(ref.transforms)) {
      ref.ancestorNamespaces = utils.findAncestorNs(doc, ref.xpath, this.namespaceResolver);
    }

    const c14nOptions = {
      inclusiveNamespacesPrefixList: ref.inclusiveNamespacesPrefixList,
      ancestorNamespaces: ref.ancestorNamespaces,
    };

    return this.getCanonXml(ref.transforms, node, c14nOptions);
  }

  private calculateSignatureValue(doc: Document, callback?: ErrorFirstCallback<string>) {
    const signedInfoCanon = this.getCanonSignedInfoXml(doc);
    const signer = this.findSignatureAlgorithm(this.signatureAlgorithm);
    if (this.privateKey == null) {
      throw new Error("Private key is required to compute signature");
    }
    if (typeof callback === "function") {
      signer.getSignature(signedInfoCanon, this.privateKey, callback);
    } else {
      const result = signer.getSignature(signedInfoCanon, this.privateKey);
      if (result instanceof Promise) {
        throw new Error(
          "Async signature algorithms cannot be used with sync methods. Use computeSignatureAsync() instead.",
        );
      }
      this.signatureValue = result;
    }
  }

  private findSignatureAlgorithm(name?: SignatureAlgorithmType) {
    if (name == null) {
      throw new Error("signatureAlgorithm is required");
    }
    const algo = this.SignatureAlgorithms[name];
    if (algo) {
      return new algo();
    } else {
      throw new Error(`signature algorithm '${name}' is not supported`);
    }
  }

  private findCanonicalizationAlgorithm(name: CanonicalizationOrTransformAlgorithmType) {
    if (name != null) {
      const algo = this.CanonicalizationAlgorithms[name];
      if (algo) {
        return new algo();
      }
    }

    throw new Error(`canonicalization algorithm '${name}' is not supported`);
  }

  private findHashAlgorithm(name: HashAlgorithmType) {
    const algo = this.HashAlgorithms[name];
    if (algo) {
      return new algo();
    } else {
      throw new Error(`hash algorithm '${name}' is not supported`);
    }
  }

  validateElementAgainstReferences(elemOrXpath: Element | string, doc: Document): Reference {
    let elem: Element;
    if (typeof elemOrXpath === "string") {
      const firstElem = xpath.select1(elemOrXpath, doc);
      isDomNode.assertIsElementNode(firstElem);
      elem = firstElem;
    } else {
      elem = elemOrXpath;
    }

    /* eslint-disable-next-line deprecation/deprecation */
    for (const ref of this.getReferences()) {
      const uri = ref.uri?.[0] === "#" ? ref.uri.substring(1) : ref.uri;

      for (const attr of this.idAttributes) {
        const elemId = elem.getAttribute(attr);
        if (uri === elemId) {
          ref.xpath = `//*[@*[local-name(.)='${attr}']='${uri}']`;
          break; // found the correct element, no need to check further
        }
      }

      const canonXml = this.getCanonReferenceXml(doc, ref, elem);
      const hash = this.findHashAlgorithm(ref.digestAlgorithm);
      const digest = hash.getHash(canonXml);

      if (utils.validateDigestValue(digest, ref.digestValue)) {
        return ref;
      }
    }

    throw new Error("No references passed validation");
  }

  private validateReference(ref: Reference, doc: Document) {
    const uri = ref.uri?.[0] === "#" ? ref.uri.substring(1) : ref.uri;
    let elem: xpath.SelectSingleReturnType = null;

    if (uri === "") {
      elem = xpath.select1("//*", doc);
    } else if (uri?.indexOf("'") !== -1) {
      // xpath injection
      throw new Error("Cannot validate a uri with quotes inside it");
    } else {
      let num_elements_for_id = 0;
      for (const attr of this.idAttributes) {
        const tmp_elemXpath = `//*[@*[local-name(.)='${attr}']='${uri}']`;
        const tmp_elem = xpath.select(tmp_elemXpath, doc);
        if (utils.isArrayHasLength(tmp_elem)) {
          num_elements_for_id += tmp_elem.length;

          if (num_elements_for_id > 1) {
            throw new Error(
              "Cannot validate a document which contains multiple elements with the " +
                "same value for the ID / Id / Id attributes, in order to prevent " +
                "signature wrapping attack.",
            );
          }

          elem = tmp_elem[0];
          ref.xpath = tmp_elemXpath;
        }
      }
    }

    ref.getValidatedNode = deprecate((xpathSelector?: string) => {
      xpathSelector = xpathSelector || ref.xpath;
      if (typeof xpathSelector !== "string" || ref.validationError != null) {
        return null;
      }
      const selectedValue = xpath.select1(xpathSelector, doc);
      return isDomNode.isNodeLike(selectedValue) ? selectedValue : null;
    }, "`ref.getValidatedNode()` is deprecated and insecure. Use `ref.signedReference` or `this.getSignedReferences()` instead.");

    if (!isDomNode.isNodeLike(elem)) {
      const validationError = new Error(
        `invalid signature: the signature references an element with uri ${ref.uri} but could not find such element in the xml`,
      );
      ref.validationError = validationError;
      return false;
    }

    const canonXml = this.getCanonReferenceXml(doc, ref, elem);
    const hash = this.findHashAlgorithm(ref.digestAlgorithm);
    const digest = hash.getHash(canonXml);

    if (digest instanceof Promise) {
      throw new Error(
        "Async algorithms cannot be used with synchronous methods. Use `checkSignatureAsync()` instead.",
      );
    }

    if (!utils.validateDigestValue(digest, ref.digestValue)) {
      const validationError = new Error(
        `invalid signature: for uri ${ref.uri} calculated digest is ${digest} but the xml to validate supplies digest ${ref.digestValue}`,
      );
      ref.validationError = validationError;

      return false;
    }
    // This step can only be done after we have verified the `signedInfo`.
    // We verified that they have same hash,
    // thus the `canonXml` and _only_ the `canonXml` can be trusted.
    // Append this to `signedReferences`.
    this.signedReferences.push(canonXml);
    ref.signedReference = canonXml;

    return true;
  }

  findSignatures(doc: Node): Node[] {
    const nodes = xpath.select(
      "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );

    return isDomNode.isArrayOfNodes(nodes) ? nodes : [];
  }

  /**
   * Loads the signature information from the provided XML node or string.
   *
   * @param signatureNode The XML node or string representing the signature.
   */
  loadSignature(signatureNode: Node | string): void {
    if (typeof signatureNode === "string") {
      const parsedDoc = new xmldom.DOMParser().parseFromString(signatureNode, "text/xml");
      this.signatureNode = signatureNode = parsedDoc.documentElement || parsedDoc;
    } else {
      this.signatureNode = signatureNode;
    }

    // Mark that the signature was explicitly loaded
    this.signatureLoadedExplicitly = true;

    this.signatureXml = signatureNode.toString();

    const node = xpath.select1(
      ".//*[local-name(.)='CanonicalizationMethod']/@Algorithm",
      signatureNode,
    );
    if (!isDomNode.isNodeLike(node)) {
      throw new Error("could not find CanonicalizationMethod/@Algorithm element");
    }

    if (isDomNode.isAttributeNode(node)) {
      this.canonicalizationAlgorithm = node.value as CanonicalizationAlgorithmType;
    }

    const signatureAlgorithm = xpath.select1(
      ".//*[local-name(.)='SignatureMethod']/@Algorithm",
      signatureNode,
    );

    if (isDomNode.isAttributeNode(signatureAlgorithm)) {
      this.signatureAlgorithm = signatureAlgorithm.value as SignatureAlgorithmType;
    }

    const signedInfoNodes = utils.findChildren(this.signatureNode, "SignedInfo");
    if (!utils.isArrayHasLength(signedInfoNodes)) {
      throw new Error("no signed info node found");
    }
    if (signedInfoNodes.length > 1) {
      throw new Error("could not load signature that contains multiple SignedInfo nodes");
    }

    // Try to operate on the c14n version of `signedInfo`. This forces the initial `getReferences()`
    // API call to always return references that are loaded under the canonical `SignedInfo`
    // in the case that the client access the `.references` **before** signature verification.

    // Ensure canonicalization algorithm is exclusive, otherwise we'd need the entire document
    let canonicalizationAlgorithmForSignedInfo = this.canonicalizationAlgorithm;
    if (
      !canonicalizationAlgorithmForSignedInfo ||
      canonicalizationAlgorithmForSignedInfo ===
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" ||
      canonicalizationAlgorithmForSignedInfo ===
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
    ) {
      canonicalizationAlgorithmForSignedInfo = "http://www.w3.org/2001/10/xml-exc-c14n#";
    }

    const temporaryCanonSignedInfo = this.getCanonXml(
      [canonicalizationAlgorithmForSignedInfo],
      signedInfoNodes[0],
    );
    const temporaryCanonSignedInfoXml = new xmldom.DOMParser().parseFromString(
      temporaryCanonSignedInfo,
      "text/xml",
    );
    const signedInfoDoc = temporaryCanonSignedInfoXml.documentElement;

    this.references = [];
    const references = utils.findChildren(signedInfoDoc, "Reference");

    if (!utils.isArrayHasLength(references)) {
      throw new Error("could not find any Reference elements");
    }

    for (const reference of references) {
      this.loadReference(reference);
    }

    const signatureValue = xpath.select1(
      ".//*[local-name(.)='SignatureValue']/text()",
      signatureNode,
    );

    if (isDomNode.isTextNode(signatureValue)) {
      this.signatureValue = signatureValue.data.replace(/\r?\n/g, "");
    }

    const keyInfo = xpath.select1(".//*[local-name(.)='KeyInfo']", signatureNode);

    if (isDomNode.isNodeLike(keyInfo)) {
      this.keyInfo = keyInfo;
    }
  }

  /**
   * Load the reference xml node to a model
   *
   */
  private loadReference(refNode: Node) {
    let nodes = utils.findChildren(refNode, "DigestMethod");
    if (nodes.length === 0) {
      throw new Error(`could not find DigestMethod in reference ${refNode.toString()}`);
    }
    const digestAlgoNode = nodes[0];

    const attr = utils.findAttr(digestAlgoNode, "Algorithm");
    if (!attr) {
      throw new Error(`could not find Algorithm attribute in node ${digestAlgoNode.toString()}`);
    }
    const digestAlgo = attr.value;

    nodes = utils.findChildren(refNode, "DigestValue");
    if (nodes.length === 0) {
      throw new Error(`could not find DigestValue node in reference ${refNode.toString()}`);
    }

    if (nodes.length > 1) {
      throw new Error(
        `could not load reference for a node that contains multiple DigestValue nodes: ${refNode.toString()}`,
      );
    }
    const digestValue = nodes[0].textContent;
    if (!digestValue) {
      throw new Error(`could not find the value of DigestValue in ${refNode.toString()}`);
    }

    const transforms: string[] = [];
    let inclusiveNamespacesPrefixList: string[] = [];
    nodes = utils.findChildren(refNode, "Transforms");
    if (nodes.length !== 0) {
      const transformsNode = nodes[0];
      const transformsAll = utils.findChildren(transformsNode, "Transform");
      for (const transform of transformsAll) {
        const transformAttr = utils.findAttr(transform, "Algorithm");

        if (transformAttr) {
          transforms.push(transformAttr.value);
        }
      }

      // This is a little strange, we are looking for children of the last child of `transformsNode`
      const inclusiveNamespaces = utils.findChildren(
        transformsAll[transformsAll.length - 1],
        "InclusiveNamespaces",
      );
      if (utils.isArrayHasLength(inclusiveNamespaces)) {
        // Should really only be one prefix list, but maybe there's some circumstances where more than one to let's handle it
        inclusiveNamespacesPrefixList = inclusiveNamespaces
          .flatMap((namespace) => (namespace.getAttribute("PrefixList") ?? "").split(" "))
          .filter((value) => value.length > 0);
      }
    }

    if (utils.isArrayHasLength(this.implicitTransforms)) {
      this.implicitTransforms.forEach(function (t) {
        transforms.push(t);
      });
    }

    /**
     * DigestMethods take an octet stream rather than a node set. If the output of the last transform is a node set, we
     * need to canonicalize the node set to an octet stream using non-exclusive canonicalization. If there are no
     * transforms, we need to canonicalize because URI dereferencing for a same-document reference will return a node-set.
     * @see:
     * https://www.w3.org/TR/xmldsig-core1/#sec-DigestMethod
     * https://www.w3.org/TR/xmldsig-core1/#sec-ReferenceProcessingModel
     * https://www.w3.org/TR/xmldsig-core1/#sec-Same-Document
     */
    if (
      transforms.length === 0 ||
      transforms[transforms.length - 1] === "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
    ) {
      transforms.push("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
    }
    const refUri = isDomNode.isElementNode(refNode)
      ? refNode.getAttribute("URI") || undefined
      : undefined;

    this.addReference({
      transforms,
      digestAlgorithm: digestAlgo,
      uri: refUri,
      digestValue,
      inclusiveNamespacesPrefixList,
      isEmptyUri: false,
    });
  }

  /**
   * Adds a reference to the signature.
   *
   * @param xpath The XPath expression to select the XML nodes to be referenced.
   * @param transforms An array of transform algorithms to be applied to the selected nodes.
   * @param digestAlgorithm The digest algorithm to use for computing the digest value.
   * @param uri The URI identifier for the reference. If empty, an empty URI will be used.
   * @param digestValue The expected digest value for the reference.
   * @param inclusiveNamespacesPrefixList The prefix list for inclusive namespace canonicalization.
   * @param isEmptyUri Indicates whether the URI is empty. Defaults to `false`.
   */
  addReference({
    xpath,
    transforms,
    digestAlgorithm,
    uri = "",
    digestValue,
    inclusiveNamespacesPrefixList = [],
    isEmptyUri = false,
  }: Partial<Reference> & Pick<Reference, "xpath">): void {
    if (digestAlgorithm == null) {
      throw new Error("digestAlgorithm is required");
    }

    if (!utils.isArrayHasLength(transforms)) {
      throw new Error("transforms must contain at least one transform algorithm");
    }

    this.references.push({
      xpath,
      transforms,
      digestAlgorithm,
      uri,
      digestValue,
      inclusiveNamespacesPrefixList,
      isEmptyUri,
      getValidatedNode: () => {
        throw new Error(
          "Reference has not been validated yet; Did you call `sig.checkSignature()`?",
        );
      },
    });
  }

  /**
   * Returns the list of references.
   */
  getReferences() {
    // TODO: Refactor once `getValidatedNode` is removed
    /* Once we completely remove the deprecated `getValidatedNode()` method,
    we can change this to return a clone to prevent accidental mutations,
    e.g.:
    return [...this.references];
    */

    return this.references;
  }

  getSignedReferences() {
    return [...this.signedReferences];
  }

  /**
   * Prepares the signature DOM structure that is common to both sync and async signature computation.
   * This method extracts the duplicated logic from computeSignature and computeSignatureAsync.
   *
   * @param doc The parsed XML document
   * @param options The signature computation options
   * @param signedInfoXml The SignedInfo XML string (generated by createSignedInfo or createSignedInfoAsync)
   * @returns An object containing the prepared DOM nodes needed for signature finalization
   */
  private prepareSignatureStructure(
    doc: Document,
    options: ComputeSignatureOptions,
    signedInfoXml: string,
  ): SignaturePreparationResult {
    let xmlNsAttr = "xmlns";
    const signatureAttrs: string[] = [];
    let currentPrefix: string;

    const validActions = ["append", "prepend", "before", "after"];

    const prefix = options.prefix;
    const attrs = options.attrs || {};
    const location = options.location || {};
    const existingPrefixes = options.existingPrefixes || {};

    this.namespaceResolver = {
      lookupNamespaceURI: function (prefix) {
        return prefix ? existingPrefixes[prefix] : null;
      },
    };

    location.reference = location.reference || "/*";
    location.action = location.action || "append";

    if (validActions.indexOf(location.action) === -1) {
      throw new Error(
        `location.action option has an invalid action: ${
          location.action
        }, must be any of the following values: ${validActions.join(", ")}`,
      );
    }

    if (prefix) {
      xmlNsAttr += `:${prefix}`;
      currentPrefix = `${prefix}:`;
    } else {
      currentPrefix = "";
    }

    Object.keys(attrs).forEach(function (name) {
      if (name !== "xmlns" && name !== xmlNsAttr) {
        signatureAttrs.push(`${name}="${attrs[name]}"`);
      }
    });

    signatureAttrs.push(`${xmlNsAttr}="http://www.w3.org/2000/09/xmldsig#"`);

    let signatureXml = `<${currentPrefix}Signature ${signatureAttrs.join(" ")}>`;
    signatureXml += signedInfoXml;
    signatureXml += this.getKeyInfo(prefix);
    signatureXml += `</${currentPrefix}Signature>`;

    this.originalXmlWithIds = doc.toString();

    let existingPrefixesString = "";
    Object.keys(existingPrefixes).forEach(function (key) {
      existingPrefixesString += `xmlns:${key}="${existingPrefixes[key]}" `;
    });

    const dummySignatureWrapper = `<Dummy ${existingPrefixesString}>${signatureXml}</Dummy>`;
    const nodeXml = new xmldom.DOMParser().parseFromString(dummySignatureWrapper);

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const signatureDoc = nodeXml.documentElement.firstChild!;

    const referenceNode = xpath.select1(location.reference, doc);

    if (!isDomNode.isNodeLike(referenceNode)) {
      throw new Error(
        `the following xpath cannot be used because it was not found: ${location.reference}`,
      );
    }

    if (location.action === "append") {
      referenceNode.appendChild(signatureDoc);
    } else if (location.action === "prepend") {
      referenceNode.insertBefore(signatureDoc, referenceNode.firstChild);
    } else if (location.action === "before") {
      if (referenceNode.parentNode == null) {
        throw new Error(
          "`location.reference` refers to the root node (by default), so we can't insert `before`",
        );
      }
      referenceNode.parentNode.insertBefore(signatureDoc, referenceNode);
    } else if (location.action === "after") {
      if (referenceNode.parentNode == null) {
        throw new Error(
          "`location.reference` refers to the root node (by default), so we can't insert `after`",
        );
      }
      referenceNode.parentNode.insertBefore(signatureDoc, referenceNode.nextSibling);
    }

    this.signatureNode = signatureDoc;
    const signedInfoNodes = utils.findChildren(this.signatureNode, "SignedInfo");
    if (signedInfoNodes.length === 0) {
      throw new Error("could not find SignedInfo element in the message");
    }
    const signedInfoNode = signedInfoNodes[0];

    return {
      doc,
      prefix,
      signatureDoc,
      signedInfoNode,
    };
  }

  /**
   * Compute the signature of the given XML (using the already defined settings).
   *
   * @param xml The XML to compute the signature for.
   * @param callback A callback function to handle the signature computation asynchronously.
   * @returns void
   * @throws TypeError If the xml can not be parsed.
   */
  computeSignature(xml: string): void;

  /**
   * Compute the signature of the given XML (using the already defined settings).
   *
   * @param xml The XML to compute the signature for.
   * @param callback A callback function to handle the signature computation asynchronously.
   * @returns void
   * @throws TypeError If the xml can not be parsed.
   */
  computeSignature(xml: string, callback: ErrorFirstCallback<SignedXml>): void;

  /**
   * Compute the signature of the given XML (using the already defined settings).
   *
   * @param xml The XML to compute the signature for.
   * @param opts An object containing options for the signature computation.
   * @returns void
   * @throws TypeError If the xml can not be parsed, or Error if there were invalid options passed.
   */
  computeSignature(xml: string, options: ComputeSignatureOptions): void;

  /**
   * Compute the signature of the given XML (using the already defined settings).
   *
   * @param xml The XML to compute the signature for.
   * @param opts An object containing options for the signature computation.
   * @param callback A callback function to handle the signature computation asynchronously.
   * @returns void
   * @throws TypeError If the xml can not be parsed, or Error if there were invalid options passed.
   */
  computeSignature(
    xml: string,
    options: ComputeSignatureOptions,
    callback: ErrorFirstCallback<SignedXml>,
  ): void;

  computeSignature(
    xml: string,
    options?: ComputeSignatureOptions | ErrorFirstCallback<SignedXml>,
    callbackParam?: ErrorFirstCallback<SignedXml>,
  ): void {
    let callback: ErrorFirstCallback<SignedXml>;
    if (typeof options === "function" && callbackParam == null) {
      callback = options as ErrorFirstCallback<SignedXml>;
      options = {} as ComputeSignatureOptions;
    } else {
      callback = callbackParam as ErrorFirstCallback<SignedXml>;
      options = (options ?? {}) as ComputeSignatureOptions;
    }

    try {
      // Parse XML and create SignedInfo synchronously
      const doc = new xmldom.DOMParser().parseFromString(xml);
      const signedInfoXml = this.createSignedInfo(doc, options.prefix);

      // Use shared preparation logic
      const {
        doc: preparedDoc,
        prefix,
        signatureDoc,
        signedInfoNode,
      } = this.prepareSignatureStructure(doc, options, signedInfoXml);

      if (typeof callback === "function") {
        // Asynchronous flow
        this.calculateSignatureValue(preparedDoc, (err, signature) => {
          if (err) {
            callback(err);
          } else {
            this.signatureValue = signature || "";
            signatureDoc.insertBefore(this.createSignature(prefix), signedInfoNode.nextSibling);
            this.signatureXml = signatureDoc.toString();
            this.signedXml = preparedDoc.toString();
            callback(null, this);
          }
        });
      } else {
        // Synchronous flow
        this.calculateSignatureValue(preparedDoc);
        signatureDoc.insertBefore(this.createSignature(prefix), signedInfoNode.nextSibling);
        this.signatureXml = signatureDoc.toString();
        this.signedXml = preparedDoc.toString();
      }
    } catch (err) {
      if (callback) {
        callback(err as Error);
      } else {
        throw err;
      }
    }
  }

  /**
   * Compute the signature of the given XML asynchronously (for use with async algorithms like WebCrypto).
   *
   * @param xml The XML to compute the signature for.
   * @param options An object containing options for the signature computation.
   * @returns Promise<SignedXml> Returns a promise that resolves to the instance of SignedXml.
   * @throws TypeError If the xml cannot be parsed, or Error if there were invalid options passed.
   */
  async computeSignatureAsync(xml: string, options?: ComputeSignatureOptions): Promise<SignedXml> {
    options = (options ?? {}) as ComputeSignatureOptions;

    // Parse XML and create SignedInfo asynchronously
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signedInfoXml = await this.createSignedInfoAsync(doc, options.prefix);

    // Use shared preparation logic
    const {
      doc: preparedDoc,
      prefix,
      signatureDoc,
      signedInfoNode,
    } = this.prepareSignatureStructure(doc, options, signedInfoXml);

    // Calculate signature asynchronously
    await this.calculateSignatureValueAsync(preparedDoc);
    signatureDoc.insertBefore(this.createSignature(prefix), signedInfoNode.nextSibling);
    this.signatureXml = signatureDoc.toString();
    this.signedXml = preparedDoc.toString();

    return this;
  }

  private async calculateSignatureValueAsync(doc: Document): Promise<void> {
    const signedInfoCanon = this.getCanonSignedInfoXml(doc);
    const signer = this.findSignatureAlgorithm(this.signatureAlgorithm);
    if (this.privateKey == null) {
      throw new Error("Private key is required to compute signature");
    }
    this.signatureValue = await Promise.resolve(
      signer.getSignature(signedInfoCanon, this.privateKey),
    );
  }

  private async createSignedInfoAsync(doc, prefix) {
    if (typeof this.canonicalizationAlgorithm !== "string") {
      throw new Error("Missing canonicalizationAlgorithm");
    }
    const transform = this.findCanonicalizationAlgorithm(this.canonicalizationAlgorithm);
    const algo = this.findSignatureAlgorithm(this.signatureAlgorithm);

    const currentPrefix = prefix || "";
    const signaturePrefix = currentPrefix ? `${currentPrefix}:` : currentPrefix;

    let res = `<${signaturePrefix}SignedInfo>`;
    res += `<${signaturePrefix}CanonicalizationMethod Algorithm="${transform.getAlgorithmName()}"`;
    if (utils.isArrayHasLength(this.inclusiveNamespacesPrefixList)) {
      res += ">";
      res += `<InclusiveNamespaces PrefixList="${this.inclusiveNamespacesPrefixList.join(
        " ",
      )}" xmlns="${transform.getAlgorithmName()}"/>`;
      res += `</${signaturePrefix}CanonicalizationMethod>`;
    } else {
      res += " />";
    }

    res += `<${signaturePrefix}SignatureMethod Algorithm="${algo.getAlgorithmName()}" />`;
    res += await this.createReferencesAsync(doc, prefix);
    res += `</${signaturePrefix}SignedInfo>`;

    return res;
  }

  private async createReferencesAsync(doc, prefix) {
    let res = "";

    prefix = prefix || "";
    prefix = prefix ? `${prefix}:` : prefix;

    /* eslint-disable-next-line deprecation/deprecation */
    for (const ref of this.getReferences()) {
      const nodes = xpath.selectWithResolver(ref.xpath ?? "", doc, this.namespaceResolver);

      if (!utils.isArrayHasLength(nodes)) {
        throw new Error(
          `the following xpath cannot be signed because it was not found: ${ref.xpath}`,
        );
      }

      for (const node of nodes) {
        if (ref.isEmptyUri) {
          res += `<${prefix}Reference URI="">`;
        } else {
          const id = this.ensureHasId(node);
          ref.uri = id;
          res += `<${prefix}Reference URI="#${id}">`;
        }
        res += `<${prefix}Transforms>`;
        for (const trans of ref.transforms || []) {
          const transform = this.findCanonicalizationAlgorithm(trans);
          res += `<${prefix}Transform Algorithm="${transform.getAlgorithmName()}"`;
          if (utils.isArrayHasLength(ref.inclusiveNamespacesPrefixList)) {
            res += ">";
            res += `<InclusiveNamespaces PrefixList="${ref.inclusiveNamespacesPrefixList.join(
              " ",
            )}" xmlns="${transform.getAlgorithmName()}"/>`;
            res += `</${prefix}Transform>`;
          } else {
            res += " />";
          }
        }

        const canonXml = this.getCanonReferenceXml(doc, ref, node);

        const digestAlgorithm = this.findHashAlgorithm(ref.digestAlgorithm);
        const digest = await Promise.resolve(digestAlgorithm.getHash(canonXml));
        res +=
          `</${prefix}Transforms>` +
          `<${prefix}DigestMethod Algorithm="${digestAlgorithm.getAlgorithmName()}" />` +
          `<${prefix}DigestValue>${digest}</${prefix}DigestValue>` +
          `</${prefix}Reference>`;
      }
    }

    return res;
  }

  private getKeyInfo(prefix) {
    const currentPrefix = prefix ? `${prefix}:` : "";

    let keyInfoAttrs = "";
    if (this.keyInfoAttributes) {
      Object.keys(this.keyInfoAttributes).forEach((name) => {
        keyInfoAttrs += ` ${name}="${this.keyInfoAttributes[name]}"`;
      });
    }

    const keyInfoContent = this.getKeyInfoContent({ publicCert: this.publicCert, prefix });
    if (keyInfoAttrs || keyInfoContent) {
      return `<${currentPrefix}KeyInfo${keyInfoAttrs}>${keyInfoContent}</${currentPrefix}KeyInfo>`;
    }

    return "";
  }

  /**
   * Generate the Reference nodes (as part of the signature process)
   *
   */
  private createReferences(doc, prefix) {
    let res = "";

    prefix = prefix || "";
    prefix = prefix ? `${prefix}:` : prefix;

    /* eslint-disable-next-line deprecation/deprecation */
    for (const ref of this.getReferences()) {
      const nodes = xpath.selectWithResolver(ref.xpath ?? "", doc, this.namespaceResolver);

      if (!utils.isArrayHasLength(nodes)) {
        throw new Error(
          `the following xpath cannot be signed because it was not found: ${ref.xpath}`,
        );
      }

      for (const node of nodes) {
        if (ref.isEmptyUri) {
          res += `<${prefix}Reference URI="">`;
        } else {
          const id = this.ensureHasId(node);
          ref.uri = id;
          res += `<${prefix}Reference URI="#${id}">`;
        }
        res += `<${prefix}Transforms>`;
        for (const trans of ref.transforms || []) {
          const transform = this.findCanonicalizationAlgorithm(trans);
          res += `<${prefix}Transform Algorithm="${transform.getAlgorithmName()}"`;
          if (utils.isArrayHasLength(ref.inclusiveNamespacesPrefixList)) {
            res += ">";
            res += `<InclusiveNamespaces PrefixList="${ref.inclusiveNamespacesPrefixList.join(
              " ",
            )}" xmlns="${transform.getAlgorithmName()}"/>`;
            res += `</${prefix}Transform>`;
          } else {
            res += " />";
          }
        }

        const canonXml = this.getCanonReferenceXml(doc, ref, node);

        const digestAlgorithm = this.findHashAlgorithm(ref.digestAlgorithm);
        res +=
          `</${prefix}Transforms>` +
          `<${prefix}DigestMethod Algorithm="${digestAlgorithm.getAlgorithmName()}" />` +
          `<${prefix}DigestValue>${digestAlgorithm.getHash(canonXml)}</${prefix}DigestValue>` +
          `</${prefix}Reference>`;
      }
    }

    return res;
  }

  getCanonXml(
    transforms: Reference["transforms"],
    node: Node,
    options: CanonicalizationOrTransformationAlgorithmProcessOptions = {},
  ) {
    options.defaultNsForPrefix = options.defaultNsForPrefix ?? SignedXml.defaultNsForPrefix;
    options.signatureNode = this.signatureNode;

    const canonXml = node.cloneNode(true); // Deep clone
    let transformedXml: Node | string = canonXml;

    transforms.forEach((transformName) => {
      if (isDomNode.isNodeLike(transformedXml)) {
        // If, after processing, `transformedNode` is a string, we can't do anymore transforms on it
        const transform = this.findCanonicalizationAlgorithm(transformName);
        transformedXml = transform.process(transformedXml, options);
      }
      //TODO: currently transform.process may return either Node or String value (enveloped transformation returns Node, exclusive-canonicalization returns String).
      //This either needs to be more explicit in the API, or all should return the same.
      //exclusive-canonicalization returns String since it builds the Xml by hand. If it had used xmldom it would incorrectly minimize empty tags
      //to <x/> instead of <x></x> and also incorrectly handle some delicate line break issues.
      //enveloped transformation returns Node since if it would return String consider this case:
      //<x xmlns:p='ns'><p:y/></x>
      //if only y is the node to sign then a string would be <p:y/> without the definition of the p namespace. probably xmldom toString() should have added it.
    });

    return transformedXml.toString();
  }

  /**
   * Ensure an element has Id attribute. If not create it with unique value.
   * Work with both normal and wssecurity Id flavour
   */
  private ensureHasId(node) {
    let attr;

    if (this.idMode === "wssecurity") {
      attr = utils.findAttr(
        node,
        "Id",
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
      );
    } else {
      this.idAttributes.some((idAttribute) => {
        attr = utils.findAttr(node, idAttribute);
        return !!attr; // This will break the loop as soon as a truthy attr is found.
      });
    }

    if (attr) {
      return attr.value;
    }

    //add the attribute
    const id = `_${this.id++}`;

    if (this.idMode === "wssecurity") {
      node.setAttributeNS(
        "http://www.w3.org/2000/xmlns/",
        "xmlns:wsu",
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
      );
      node.setAttributeNS(
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
        "wsu:Id",
        id,
      );
    } else {
      node.setAttribute("Id", id);
    }

    return id;
  }

  /**
   * Create the SignedInfo element
   *
   */
  private createSignedInfo(doc, prefix) {
    if (typeof this.canonicalizationAlgorithm !== "string") {
      throw new Error(
        "Missing canonicalizationAlgorithm when trying to create signed info for XML",
      );
    }
    const transform = this.findCanonicalizationAlgorithm(this.canonicalizationAlgorithm);
    const algo = this.findSignatureAlgorithm(this.signatureAlgorithm);
    let currentPrefix;

    currentPrefix = prefix || "";
    currentPrefix = currentPrefix ? `${currentPrefix}:` : currentPrefix;

    let res = `<${currentPrefix}SignedInfo>`;
    res += `<${currentPrefix}CanonicalizationMethod Algorithm="${transform.getAlgorithmName()}"`;
    if (utils.isArrayHasLength(this.inclusiveNamespacesPrefixList)) {
      res += ">";
      res += `<InclusiveNamespaces PrefixList="${this.inclusiveNamespacesPrefixList.join(
        " ",
      )}" xmlns="${transform.getAlgorithmName()}"/>`;
      res += `</${currentPrefix}CanonicalizationMethod>`;
    } else {
      res += " />";
    }
    res += `<${currentPrefix}SignatureMethod Algorithm="${algo.getAlgorithmName()}" />`;

    res += this.createReferences(doc, prefix);
    res += `</${currentPrefix}SignedInfo>`;
    return res;
  }

  /**
   * Create the Signature element
   *
   */
  private createSignature(prefix?: string) {
    let xmlNsAttr = "xmlns";

    if (prefix) {
      xmlNsAttr += `:${prefix}`;
      prefix += ":";
    } else {
      prefix = "";
    }

    const signatureValueXml = `<${prefix}SignatureValue>${this.signatureValue}</${prefix}SignatureValue>`;
    //the canonicalization requires to get a valid xml node.
    //we need to wrap the info in a dummy signature since it contains the default namespace.
    const dummySignatureWrapper = `<${prefix}Signature ${xmlNsAttr}="http://www.w3.org/2000/09/xmldsig#">${signatureValueXml}</${prefix}Signature>`;

    const doc = new xmldom.DOMParser().parseFromString(dummySignatureWrapper);

    // Because we are using a dummy wrapper hack described above, we know there will be a `firstChild`
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return doc.documentElement.firstChild!;
  }

  /**
   * Returns just the signature part, must be called only after {@link computeSignature}
   *
   * @returns The signature XML.
   */
  getSignatureXml(): string {
    return this.signatureXml;
  }

  /**
   * Returns the original xml with Id attributes added on relevant elements (required for validation), must be called only after {@link computeSignature}
   *
   * @returns The original XML with IDs.
   */
  getOriginalXmlWithIds(): string {
    return this.originalXmlWithIds;
  }

  /**
   * Returns the original xml document with the signature in it, must be called only after {@link computeSignature}
   *
   * @returns The signed XML.
   */
  getSignedXml(): string {
    if (this.signedXml === undefined) {
      throw new Error(
        "signedXml is not set. Call computeSignature() or computeSignatureAsync() first.",
      );
    }
    return this.signedXml;
  }
}
