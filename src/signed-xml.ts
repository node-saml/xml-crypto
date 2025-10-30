import type {
  CanonicalizationAlgorithmURI,
  TransformAlgorithmURI,
  TransformAlgorithmOptions,
  ComputeSignatureOptions,
  ErrorFirstCallback,
  GetKeyInfoContentArgs,
  HashAlgorithmURI,
  IdAttributeType,
  ObjectAttributes,
  Reference,
  SignatureAlgorithmURI,
  SignedXmlOptions,
  HashAlgorithmMap,
  SignatureAlgorithmMap,
  CanonicalizationAlgorithmMap,
  TransformAlgorithmMap,
  VerificationIdAttributeType,
} from "./types";

import * as isDomNode from "@xmldom/is-dom-node";
import * as xmldom from "@xmldom/xmldom";
import * as crypto from "crypto";
import { deprecate } from "util";
import * as xpath from "xpath";
import * as c14n from "./c14n-canonicalization";
import * as envelopedSignatures from "./enveloped-signature";
import * as execC14n from "./exclusive-canonicalization";
import * as hashAlgorithms from "./hash-algorithms";
import * as signatureAlgorithms from "./signature-algorithms";
import * as utils from "./utils";
import { XMLDSIG_URIS } from "./xmldsig-uris";
const {
  CANONICALIZATION_ALGORITHMS,
  HASH_ALGORITHMS,
  SIGNATURE_ALGORITHMS,
  TRANSFORM_ALGORITHMS,
  NAMESPACES,
} = XMLDSIG_URIS;

export class SignedXml {
  /**
   * Specifies the mode to use when searching for ID attributes.
   * Planned for deprecation. Use `idAttributes` instead with value [{ prefix: "wsu", localName: "Id", namespaceUri: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" }]
   */
  idMode?: "wssecurity";
  /**
   * Specifies the Id attributes which will be used to resolve reference URIs.
   * When signing, if no Id attribute is found on the element to be signed the first one from this list will be added.
   * If idAttribute is also specified, it will be added to the start of this list.
   *
   * @default {@link SignedXml.getDefaultIdAttributes()}
   * @example [{localName: "Id", namespaceUri: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" }]
   */
  idAttributes: IdAttributeType[];
  /**
   * A {@link Buffer} or pem encoded {@link String} containing your private key
   */
  privateKey?: crypto.KeyLike;
  publicCert?: crypto.KeyLike;
  /**
   * One of the supported signature algorithms.
   * @see {@link SignatureAlgorithmURI}
   */
  signatureAlgorithm?: SignatureAlgorithmURI = undefined;
  /**
   * Rules used to convert an XML document into its canonical form.
   */
  canonicalizationAlgorithm?: CanonicalizationAlgorithmURI = undefined;
  /**
   * It specifies a list of namespace prefixes that should be considered "inclusive" during the canonicalization process.
   * Only applicable when using exclusive canonicalization.
   */
  inclusiveNamespacesPrefixList: string[] = [];
  namespaceResolver: XPathNSResolver = {
    lookupNamespaceURI: function (/* prefix */) {
      throw new Error("Not implemented");
    },
  };

  maxTransforms: number | null;
  implicitTransforms: ReadonlyArray<TransformAlgorithmURI> = [];
  keyInfoAttributes: { [attrName: string]: string } = {};
  getKeyInfoContent = SignedXml.getKeyInfoContent;
  getCertFromKeyInfo = SignedXml.getCertFromKeyInfo;
  objects?: Array<{ content: string; attributes?: ObjectAttributes }>;

  // Internal state
  private id = 0;
  private signedXml = "";
  private signatureXml = "";
  private signatureNode: Node | null = null;
  private signatureValue = "";
  private originalXmlWithIds = "";
  private keyInfo: Node | null = null;

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
   *  To add a new transformation algorithm create a new class that implements the {@link CanonicalizationAlgorithm} interface, and register it here. More info: {@link https://github.com/node-saml/xml-crypto#customizing-algorithms|Customizing Algorithms}
   */
  CanonicalizationAlgorithms: CanonicalizationAlgorithmMap;

  /**
   * To add a new hash algorithm create a new class that implements the {@link HashAlgorithm} interface, and register it here. More info: {@link https://github.com/node-saml/xml-crypto#customizing-algorithms|Customizing Algorithms}
   */
  HashAlgorithms: HashAlgorithmMap;

  /**
   * To add a new signature algorithm create a new class that implements the {@link SignatureAlgorithm} interface, and register it here. More info: {@link https://github.com/node-saml/xml-crypto#customizing-algorithms|Customizing Algorithms}
   */
  SignatureAlgorithms: SignatureAlgorithmMap;

  /**
   * To add a new transformation algorithm create a new class that implements the {@link TransformAlgorithm} interface, and register it here.
   */
  TransformAlgorithms: TransformAlgorithmMap | undefined;

  static defaultNsForPrefix = {
    ds: NAMESPACES.ds,
  };

  static noop = () => null;

  static readonly getDefaultCanonicalizationAlgorithms = (): CanonicalizationAlgorithmMap => ({
    [CANONICALIZATION_ALGORITHMS.C14N]: c14n.C14nCanonicalization,
    [CANONICALIZATION_ALGORITHMS.C14N_WITH_COMMENTS]: c14n.C14nCanonicalizationWithComments,
    [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N]: execC14n.ExclusiveCanonicalization,
    [CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N_WITH_COMMENTS]:
      execC14n.ExclusiveCanonicalizationWithComments,
    // TODO: separate TransformAlgorithms from CanonicalizationAlgorithms
    [TRANSFORM_ALGORITHMS.ENVELOPED_SIGNATURE]: envelopedSignatures.EnvelopedSignature,
  });

  static readonly getDefaultHashAlgorithms = (): HashAlgorithmMap => ({
    // TODO: In v7.x we may consider removing sha1 from defaults
    [HASH_ALGORITHMS.SHA1]: hashAlgorithms.Sha1,
    [HASH_ALGORITHMS.SHA256]: hashAlgorithms.Sha256,
    [HASH_ALGORITHMS.SHA512]: hashAlgorithms.Sha512,
  });

  static readonly getDefaultSignatureAlgorithms = (): SignatureAlgorithmMap => ({
    // TODO: In v7.x we may consider removing rsa-sha1 from defaults
    [SIGNATURE_ALGORITHMS.RSA_SHA1]: signatureAlgorithms.RsaSha1,
    [SIGNATURE_ALGORITHMS.RSA_SHA256]: signatureAlgorithms.RsaSha256,
    [SIGNATURE_ALGORITHMS.RSA_SHA256_MGF1]: signatureAlgorithms.RsaSha256Mgf1,
    [SIGNATURE_ALGORITHMS.RSA_SHA512]: signatureAlgorithms.RsaSha512,
    // Disabled by default due to key confusion concerns.
    // 'http://www.w3.org/2000/09/xmldsig#hmac-sha1': SignatureAlgorithms.HmacSha1
  });

  static readonly getDefaultTransformAlgorithms = (): TransformAlgorithmMap =>
    SignedXml.getDefaultCanonicalizationAlgorithms();

  static readonly getDefaultIdAttributes = (): VerificationIdAttributeType[] => ["Id", "ID", "id"];

  /**
   * The SignedXml constructor provides an abstraction for sign and verify xml documents. The object is constructed using
   * @param options {@link SignedXmlOptions}
   */
  constructor(options: SignedXmlOptions = {}) {
    const {
      idMode,
      idAttribute,
      idAttributes,
      privateKey,
      publicCert,
      signatureAlgorithm,
      canonicalizationAlgorithm,
      inclusiveNamespacesPrefixList,
      maxTransforms,
      implicitTransforms,
      keyInfoAttributes,
      getKeyInfoContent,
      getCertFromKeyInfo,
      objects,
      allowedSignatureAlgorithms,
      allowedHashAlgorithms,
      allowedCanonicalizationAlgorithms,
      allowedTransformAlgorithms,
    } = options;

    // Options
    this.idMode = idMode;
    this.idAttributes = idAttributes ?? SignedXml.getDefaultIdAttributes();
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
    this.maxTransforms = maxTransforms ?? null;
    this.implicitTransforms = implicitTransforms ?? this.implicitTransforms;
    this.keyInfoAttributes = keyInfoAttributes ?? this.keyInfoAttributes;
    this.getKeyInfoContent = getKeyInfoContent ?? this.getKeyInfoContent;
    this.getCertFromKeyInfo = getCertFromKeyInfo ?? SignedXml.noop;
    this.objects = objects;
    this.CanonicalizationAlgorithms =
      allowedCanonicalizationAlgorithms ?? SignedXml.getDefaultCanonicalizationAlgorithms();
    this.HashAlgorithms = allowedHashAlgorithms ?? SignedXml.getDefaultHashAlgorithms();
    this.SignatureAlgorithms =
      allowedSignatureAlgorithms ?? SignedXml.getDefaultSignatureAlgorithms();
    // TODO: use default transform algorithms if not provided (breaking change)
    this.TransformAlgorithms = allowedTransformAlgorithms;
  }

  /**
   * Due to key-confusion issues, it's risky to have both hmac
   * and digital signature algorithms enabled at the same time.
   * This enables HMAC and disables other signing algorithms.
   */
  enableHMAC(): void {
    this.SignatureAlgorithms = {
      [SIGNATURE_ALGORITHMS.HMAC_SHA1]: signatureAlgorithms.HmacSha1,
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

    this.signedXml = xml;

    const doc = new xmldom.DOMParser().parseFromString(xml);

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
        );
        return; // return early
      } else {
        throw new Error(
          `invalid signature: the signature value ${this.signatureValue} is incorrect`,
        );
      }
    }
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
      this.canonicalizationAlgorithm === CANONICALIZATION_ALGORITHMS.C14N ||
      this.canonicalizationAlgorithm === CANONICALIZATION_ALGORITHMS.C14N_WITH_COMMENTS
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
      this.signatureValue = signer.getSignature(signedInfoCanon, this.privateKey);
    }
  }

  private findSignatureAlgorithm(name?: SignatureAlgorithmURI) {
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

  private findCanonicalizationAlgorithm(name: CanonicalizationAlgorithmURI) {
    if (name != null) {
      const algo = this.CanonicalizationAlgorithms[name];
      if (algo) {
        return new algo();
      }
    }

    throw new Error(`canonicalization algorithm '${name}' is not supported`);
  }

  private findHashAlgorithm(name: HashAlgorithmURI) {
    const algo = this.HashAlgorithms[name];
    if (algo) {
      return new algo();
    } else {
      throw new Error(`hash algorithm '${name}' is not supported`);
    }
  }

  private findTransformAlgorithm(name: TransformAlgorithmURI) {
    // TODO: remove this fallback (breaking change)
    if (this.TransformAlgorithms == null) {
      return this.findCanonicalizationAlgorithm(name);
    }
    const algo = this.TransformAlgorithms[name];
    if (algo) {
      return new algo();
    } else {
      throw new Error(`transform algorithm '${name}' is not supported`);
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

      for (const idAttr of this.idAttributes) {
        if (typeof idAttr === "string") {
          if (uri === elem.getAttribute(idAttr)) {
            // We look for attributes in any namespace or no namespace
            ref.xpath = `//*[@*[local-name(.)='${idAttr}']='${uri}']`;
            break; // found the correct element, no need to check further
          }
        } else {
          const attr = utils.findAttr(elem, idAttr.localName, idAttr.namespaceUri);
          if (attr && uri === attr.value) {
            if (idAttr.namespaceUri !== undefined) {
              // When namespaceUri is set, we look for attributes in that specific namespace
              ref.xpath = `//*[@*[local-name(.)='${idAttr.localName}' and namespace-uri(.)='${idAttr.namespaceUri}']='${uri}']`;
            } else {
              // When namespaceUri is explicitly set to undefined, we look only for attributes without a namespace
              ref.xpath = `//*[@*[local-name(.)='${idAttr.localName}' and namespace-uri(.)='']='${uri}']`;
            }
            break; // found the correct element, no need to check further
          }
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
      for (const idAttr of this.idAttributes) {
        let tmp_elemXpath: string;

        if (typeof idAttr === "string") {
          tmp_elemXpath = `//*[@*[local-name(.)='${idAttr}']='${uri}']`;
        } else {
          if (idAttr.namespaceUri) {
            tmp_elemXpath = `//*[@*[local-name(.)='${idAttr.localName}' and namespace-uri(.)='${idAttr.namespaceUri}']='${uri}']`;
          } else {
            tmp_elemXpath = `//*[@*[local-name(.)='${idAttr.localName}']='${uri}']`;
          }
        }

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
      `//*[local-name(.)='Signature' and namespace-uri(.)='${NAMESPACES.ds}']`,
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
      this.signatureNode = signatureNode = new xmldom.DOMParser().parseFromString(signatureNode);
    } else {
      this.signatureNode = signatureNode;
    }

    this.signatureXml = signatureNode.toString();

    const node = xpath.select1(
      ".//*[local-name(.)='CanonicalizationMethod']/@Algorithm",
      signatureNode,
    );
    if (!isDomNode.isNodeLike(node)) {
      throw new Error("could not find CanonicalizationMethod/@Algorithm element");
    }

    if (isDomNode.isAttributeNode(node)) {
      this.canonicalizationAlgorithm = node.value as CanonicalizationAlgorithmURI;

      if (!this.findCanonicalizationAlgorithm(this.canonicalizationAlgorithm)) {
        throw new Error(
          `unsupported canonicalization algorithm: ${this.canonicalizationAlgorithm}`,
        );
      }
    }

    const signatureAlgorithm = xpath.select1(
      ".//*[local-name(.)='SignatureMethod']/@Algorithm",
      signatureNode,
    );

    if (isDomNode.isAttributeNode(signatureAlgorithm)) {
      this.signatureAlgorithm = signatureAlgorithm.value as SignatureAlgorithmURI;
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
      canonicalizationAlgorithmForSignedInfo === CANONICALIZATION_ALGORITHMS.C14N ||
      canonicalizationAlgorithmForSignedInfo === CANONICALIZATION_ALGORITHMS.C14N_WITH_COMMENTS
    ) {
      canonicalizationAlgorithmForSignedInfo = CANONICALIZATION_ALGORITHMS.EXCLUSIVE_C14N;
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
      transforms[transforms.length - 1] === TRANSFORM_ALGORITHMS.ENVELOPED_SIGNATURE
    ) {
      transforms.push(CANONICALIZATION_ALGORITHMS.C14N);
    }
    const refUri = isDomNode.isElementNode(refNode)
      ? refNode.getAttribute("URI") || undefined
      : undefined;

    if (this.maxTransforms !== null) {
      if (transforms.length > this.maxTransforms) {
        throw new Error(
          `Number of transforms (${transforms.length}) exceeds the maximum allowed (${this.maxTransforms})`,
        );
      }
    }

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
   * @param id An optional `Id` attribute for the reference.
   * @param type An optional `Type` attribute for the reference.
   */
  addReference({
    xpath,
    transforms,
    digestAlgorithm,
    uri = "",
    digestValue,
    inclusiveNamespacesPrefixList = [],
    isEmptyUri = false,
    id = undefined,
    type = undefined,
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
      id,
      type,
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
   * @returns If no callback is provided, returns `this` (the instance of SignedXml).
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

    const doc = new xmldom.DOMParser().parseFromString(xml);
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

    // defaults to the root node
    location.reference = location.reference || "/*";
    // defaults to append action
    location.action = location.action || "append";

    if (validActions.indexOf(location.action) === -1) {
      const err = new Error(
        `location.action option has an invalid action: ${
          location.action
        }, must be any of the following values: ${validActions.join(", ")}`,
      );
      if (!callback) {
        throw err;
      } else {
        callback(err);
        return;
      }
    }

    // Add IDs for all non-self references upfront
    for (const ref of this.getReferences()) {
      if (ref.isEmptyUri) {
        continue;
      } // No specific nodes to ID for empty URI

      const nodes = xpath.selectWithResolver(
        ref.xpath ?? "",
        doc,
        this.namespaceResolver,
      ) as Element[];
      for (const node of nodes) {
        isDomNode.assertIsElementNode(node);
        this.ensureHasId(node);
      }
    }

    // Capture original with IDs (no sig yet)
    this.originalXmlWithIds = doc.toString();

    // automatic insertion of `:`
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

    // add the xml namespace attribute
    signatureAttrs.push(`${xmlNsAttr}="http://www.w3.org/2000/09/xmldsig#"`);

    let signatureXml = `<${currentPrefix}Signature ${signatureAttrs.join(" ")}>`;

    signatureXml += this.createSignedInfo(doc, prefix);
    signatureXml += this.getKeyInfo(prefix);
    signatureXml += this.getObjects(prefix);
    signatureXml += `</${currentPrefix}Signature>`;

    let existingPrefixesString = "";
    Object.keys(existingPrefixes).forEach(function (key) {
      existingPrefixesString += `xmlns:${key}="${existingPrefixes[key]}" `;
    });

    // A trick to remove the namespaces that already exist in the xml
    // This only works if the prefix and namespace match with those in the xml
    const dummySignatureWrapper = `<Dummy ${existingPrefixesString}>${signatureXml}</Dummy>`;
    const nodeXml = new xmldom.DOMParser().parseFromString(dummySignatureWrapper);

    // Because we are using a dummy wrapper hack described above, we know there will be a `firstChild`
    // and that it will be an `Element` node.
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const signatureElem = nodeXml.documentElement.firstChild! as Element;

    const referenceNode = xpath.select1(location.reference, doc);

    if (!isDomNode.isNodeLike(referenceNode)) {
      const err2 = new Error(
        `the following xpath cannot be used because it was not found: ${location.reference}`,
      );
      if (!callback) {
        throw err2;
      } else {
        callback(err2);
        return;
      }
    }

    if (location.action === "append") {
      referenceNode.appendChild(signatureElem);
    } else if (location.action === "prepend") {
      referenceNode.insertBefore(signatureElem, referenceNode.firstChild);
    } else if (location.action === "before") {
      if (referenceNode.parentNode == null) {
        throw new Error(
          "`location.reference` refers to the root node (by default), so we can't insert `before`",
        );
      }
      referenceNode.parentNode.insertBefore(signatureElem, referenceNode);
    } else if (location.action === "after") {
      if (referenceNode.parentNode == null) {
        throw new Error(
          "`location.reference` refers to the root node (by default), so we can't insert `after`",
        );
      }
      referenceNode.parentNode.insertBefore(signatureElem, referenceNode.nextSibling);
    }

    // Now add all references (including any to the signature itself)
    this.addAllReferences(doc, signatureElem, prefix);

    this.signatureNode = signatureElem;
    const signedInfoNodes = utils.findChildren(this.signatureNode, "SignedInfo");
    if (signedInfoNodes.length === 0) {
      const err3 = new Error("could not find SignedInfo element in the message");
      if (!callback) {
        throw err3;
      } else {
        callback(err3);
        return;
      }
    }
    const signedInfoNode = signedInfoNodes[0];

    if (typeof callback === "function") {
      // Asynchronous flow
      this.calculateSignatureValue(doc, (err, signature) => {
        if (err) {
          callback(err);
        } else {
          this.signatureValue = signature || "";
          signatureElem.insertBefore(this.createSignature(prefix), signedInfoNode.nextSibling);
          this.signatureXml = signatureElem.toString();
          this.signedXml = doc.toString();
          callback(null, this);
        }
      });
    } else {
      // Synchronous flow
      this.calculateSignatureValue(doc);
      signatureElem.insertBefore(this.createSignature(prefix), signedInfoNode.nextSibling);
      this.signatureXml = signatureElem.toString();
      this.signedXml = doc.toString();
    }
  }

  /**
   * Adds all references to the SignedInfo after the signature placeholder is inserted.
   */
  private addAllReferences(doc: Document, signatureElem: Element, prefix?: string): void {
    if (!utils.isArrayHasLength(this.references)) {
      return;
    }

    const currentPrefix = prefix ? `${prefix}:` : "";
    const signatureNamespace = XMLDSIG_URIS.NAMESPACES.ds;

    // Find the SignedInfo element to append to
    const signedInfoNode = xpath.select1(`./*[local-name(.)='SignedInfo']`, signatureElem);
    isDomNode.assertIsElementNode(signedInfoNode); // Type-safe assertion

    // Signature document is technically the same document as the one we are signing,
    // but we will extract it here for clarity (and also make it support detached signatures in the future)
    const signatureDoc = signatureElem.ownerDocument;

    // Process each reference
    for (const ref of this.getReferences()) {
      const nodes = xpath.selectWithResolver(ref.xpath ?? "", doc, this.namespaceResolver);

      if (!utils.isArrayHasLength(nodes)) {
        throw new Error(
          `the following xpath cannot be signed because it was not found: ${ref.xpath}`,
        );
      }

      // Process the reference
      for (const node of nodes) {
        isDomNode.assertIsElementNode(node);

        // Must not be a reference to Signature, SignedInfo, or a child of SignedInfo
        if (
          node === signatureElem ||
          node === signedInfoNode ||
          utils.isDescendantOf(node, signedInfoNode)
        ) {
          throw new Error(
            `Cannot sign a reference to the Signature or SignedInfo element itself: ${ref.xpath}`,
          );
        }

        // Compute the target URI (ID already ensured earlier, extract it)
        let targetUri: string;
        if (ref.isEmptyUri) {
          targetUri = "";
        } else {
          const id = this.ensureHasId(node);
          ref.uri = id;
          targetUri = `#${id}`;
        }

        // Create the reference element directly using DOM methods to avoid namespace issues
        const referenceElem = signatureDoc.createElementNS(
          signatureNamespace,
          `${currentPrefix}Reference`,
        );
        referenceElem.setAttribute("URI", targetUri);

        if (ref.id) {
          referenceElem.setAttribute("Id", ref.id);
        }

        if (ref.type) {
          referenceElem.setAttribute("Type", ref.type);
        }

        const transformsElem = signatureDoc.createElementNS(
          signatureNamespace,
          `${currentPrefix}Transforms`,
        );

        for (const trans of ref.transforms || []) {
          const transform = this.findTransformAlgorithm(trans);
          const transformElem = signatureDoc.createElementNS(
            signatureNamespace,
            `${currentPrefix}Transform`,
          );
          transformElem.setAttribute("Algorithm", transform.getAlgorithmName());

          if (utils.isArrayHasLength(ref.inclusiveNamespacesPrefixList)) {
            const inclusiveNamespacesElem = signatureDoc.createElementNS(
              transform.getAlgorithmName(),
              "InclusiveNamespaces",
            );
            inclusiveNamespacesElem.setAttribute(
              "PrefixList",
              ref.inclusiveNamespacesPrefixList.join(" "),
            );
            transformElem.appendChild(inclusiveNamespacesElem);
          }

          transformsElem.appendChild(transformElem);
        }

        // Get the canonicalized XML
        const canonXml = this.getCanonReferenceXml(doc, ref, node);

        // Get the digest algorithm and compute the digest value
        const digestAlgorithm = this.findHashAlgorithm(ref.digestAlgorithm);

        const digestMethodElem = signatureDoc.createElementNS(
          signatureNamespace,
          `${currentPrefix}DigestMethod`,
        );
        digestMethodElem.setAttribute("Algorithm", digestAlgorithm.getAlgorithmName());

        const digestValueElem = signatureDoc.createElementNS(
          signatureNamespace,
          `${currentPrefix}DigestValue`,
        );
        digestValueElem.textContent = digestAlgorithm.getHash(canonXml);

        referenceElem.appendChild(transformsElem);
        referenceElem.appendChild(digestMethodElem);
        referenceElem.appendChild(digestValueElem);

        // Append the reference element to SignedInfo
        signedInfoNode.appendChild(referenceElem);
      }
    }
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
   * Creates XML for Object elements to be included in the signature
   *
   * @param prefix Optional namespace prefix
   * @returns XML string with Object elements or empty string if none
   */
  private getObjects(prefix?: string) {
    const currentPrefix = prefix ? `${prefix}:` : "";

    if (!this.objects || this.objects.length === 0) {
      return "";
    }

    let result = "";

    for (const obj of this.objects) {
      let objectAttrs = "";
      if (obj.attributes) {
        Object.keys(obj.attributes).forEach((name) => {
          const value = obj.attributes?.[name];
          if (value !== undefined) {
            objectAttrs += ` ${name}="${value}"`;
          }
        });
      }

      result += `<${currentPrefix}Object${objectAttrs}>${obj.content}</${currentPrefix}Object>`;
    }

    return result;
  }

  getCanonXml(
    transforms: Reference["transforms"],
    node: Node,
    options: TransformAlgorithmOptions = {},
  ) {
    options.defaultNsForPrefix = options.defaultNsForPrefix ?? SignedXml.defaultNsForPrefix;
    options.signatureNode = this.signatureNode;

    const canonXml = node.cloneNode(true); // Deep clone
    let transformedXml: Node | string = canonXml;

    transforms.forEach((transformName) => {
      if (isDomNode.isNodeLike(transformedXml)) {
        // If, after processing, `transformedNode` is a string, we can't do anymore transforms on it
        const transform = this.findTransformAlgorithm(transformName);
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
      attr = utils.findAttr(node, "Id", XMLDSIG_URIS.NAMESPACES.wsu);
    } else {
      this.idAttributes.some((idAttribute) => {
        if (typeof idAttribute === "string") {
          attr = utils.findAttr(node, idAttribute);
        } else {
          attr = utils.findAttr(node, idAttribute.localName, idAttribute.namespaceUri);
        }
        return !!attr; // This will break the loop as soon as a truthy attr is found.
      });
    }

    if (attr) {
      return attr.value;
    }

    //add the attribute
    const id = `_${this.id++}`;

    if (this.idMode === "wssecurity") {
      node.setAttributeNS(NAMESPACES.xmlns, "xmlns:wsu", NAMESPACES.wsu);
      node.setAttributeNS(NAMESPACES.wsu, "wsu:Id", id);
    } else {
      // Use the first idAttribute to set the new ID
      const firstIdAttr = this.idAttributes[0];
      if (typeof firstIdAttr === "string") {
        node.setAttribute(firstIdAttr, id);
      } else {
        if ("prefix" in firstIdAttr && firstIdAttr.prefix) {
          node.setAttributeNS(
            NAMESPACES.xmlns,
            `xmlns:${firstIdAttr.prefix}`,
            firstIdAttr.namespaceUri,
          );
          node.setAttributeNS(
            firstIdAttr.namespaceUri,
            `${firstIdAttr.prefix}:${firstIdAttr.localName}`,
            id,
          );
        } else {
          node.setAttribute(firstIdAttr.localName, id);
        }
      }
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
    const canonicalization = this.findCanonicalizationAlgorithm(this.canonicalizationAlgorithm);
    const algo = this.findSignatureAlgorithm(this.signatureAlgorithm);
    const currentPrefix = prefix ? `${prefix}:` : "";

    let res = `<${currentPrefix}SignedInfo>`;
    res += `<${currentPrefix}CanonicalizationMethod Algorithm="${canonicalization.getAlgorithmName()}"`;
    if (utils.isArrayHasLength(this.inclusiveNamespacesPrefixList)) {
      res += ">";
      res += `<InclusiveNamespaces PrefixList="${this.inclusiveNamespacesPrefixList.join(
        " ",
      )}" xmlns="${canonicalization.getAlgorithmName()}"/>`;
      res += `</${currentPrefix}CanonicalizationMethod>`;
    } else {
      res += " />";
    }
    res += `<${currentPrefix}SignatureMethod Algorithm="${algo.getAlgorithmName()}" />`;

    // No references here - added later
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
    const dummySignatureWrapper = `<${prefix}Signature ${xmlNsAttr}="${NAMESPACES.ds}">${signatureValueXml}</${prefix}Signature>`;

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
    return this.signedXml;
  }
}
