const xpath = require("xpath");
const Dom = require("@xmldom/xmldom").DOMParser;
const utils = require("./utils");
const c14n = require("./c14n-canonicalization");
const execC14n = require("./exclusive-canonicalization");
const EnvelopedSignature = require("./enveloped-signature").EnvelopedSignature;
const hashAlgorithms = require("./hash-algorithms");
const signatureAlgorithms = require("./signature-algorithms");

/**
 * @type {import ("../index.d.ts").SignedXml}
 */
class SignedXml {
  constructor(idMode, options = {}) {
    this.options = options;
    this.idMode = idMode;
    this.references = [];
    this.id = 0;
    this.privateKey = null;
    this.publicCert = null;
    this.signatureAlgorithm =
      this.options.signatureAlgorithm || "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    this.canonicalizationAlgorithm =
      this.options.canonicalizationAlgorithm || "http://www.w3.org/2001/10/xml-exc-c14n#";
    this.inclusiveNamespacesPrefixList = this.options.inclusiveNamespacesPrefixList || "";
    this.signedXml = "";
    this.signatureXml = "";
    this.signatureNode = null;
    this.signatureValue = "";
    this.originalXmlWithIds = "";
    this.validationErrors = [];
    this.keyInfo = null;
    this.idAttributes = ["Id", "ID", "id"];
    if (this.options.idAttribute) {
      this.idAttributes.unshift(this.options.idAttribute);
    }
    this.implicitTransforms = this.options.implicitTransforms || [];
    this.getKeyInfoContent = SignedXml.getKeyInfoContent;
    this.getCertFromKeyInfo = SignedXml.getCertFromKeyInfo;
    this.keyInfoAttributes = {};

    this.CanonicalizationAlgorithms = {
      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315": c14n.C14nCanonicalization,
      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments":
        c14n.C14nCanonicalizationWithComments,
      "http://www.w3.org/2001/10/xml-exc-c14n#": execC14n.ExclusiveCanonicalization,
      "http://www.w3.org/2001/10/xml-exc-c14n#WithComments":
        execC14n.ExclusiveCanonicalizationWithComments,
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature": EnvelopedSignature,
    };

    this.HashAlgorithms = {
      "http://www.w3.org/2000/09/xmldsig#sha1": hashAlgorithms.Sha1,
      "http://www.w3.org/2001/04/xmlenc#sha256": hashAlgorithms.Sha256,
      "http://www.w3.org/2001/04/xmlenc#sha512": hashAlgorithms.Sha512,
    };

    this.SignatureAlgorithms = {
      "http://www.w3.org/2000/09/xmldsig#rsa-sha1": signatureAlgorithms.RsaSha1,
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": signatureAlgorithms.RsaSha256,
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": signatureAlgorithms.RsaSha512,
      // Disabled by default due to key confusion concerns.
      // 'http://www.w3.org/2000/09/xmldsig#hmac-sha1': SignatureAlgorithms.HmacSha1
    };
  }

  /**
   * Due to key-confusion issues, its risky to have both hmac
   * and digital signature algos enabled at the same time.
   * This enables HMAC and disables other signing algos.
   */
  enableHMAC() {
    this.SignatureAlgorithms = {
      "http://www.w3.org/2000/09/xmldsig#hmac-sha1": signatureAlgorithms.HmacSha1,
    };
    this.getKeyInfoContent = () => null;
  }

  static getKeyInfoContent({ publicCert = null, prefix = null } = {}) {
    if (publicCert == null) {
      return null;
    }

    prefix = prefix ? prefix + ":" : "";

    let x509Certs = "";
    if (Buffer.isBuffer(publicCert)) {
      publicCert = publicCert.toString("latin1");
    }

    if (typeof publicCert === "string") {
      publicCert = publicCert.match(utils.EXTRACT_X509_CERTS);
    }

    if (Array.isArray(publicCert)) {
      x509Certs = publicCert
        .map((c) => `<X509Certificate>${utils.pemToDer(c)}</X509Certificate>`)
        .join("");
    }

    return `<${prefix}X509Data>${x509Certs}</${prefix}X509Data>`;
  }

  static getCertFromKeyInfo(keyInfo) {
    if (keyInfo != null && keyInfo.length > 0) {
      const certs = xpath.select(".//*[local-name(.)='X509Certificate']", keyInfo[0]);
      if (certs.length > 0) {
        return utils.derToPem(certs[0].textContent.trim(), "CERTIFICATE");
      }
    }

    return null;
  }

  checkSignature(xml, callback) {
    if (callback != null && typeof callback !== "function") {
      throw new Error("Last parameter must be a callback function");
    }

    this.validationErrors = [];
    this.signedXml = xml;

    const doc = new Dom().parseFromString(xml);

    if (!this.validateReferences(doc)) {
      if (!callback) {
        return false;
      } else {
        callback(new Error("Could not validate references"));
        return;
      }
    }

    if (!callback) {
      // Synchronous flow
      if (!this.validateSignatureValue(doc)) {
        return false;
      }
      return true;
    } else {
      // Asynchronous flow
      this.validateSignatureValue(doc, function (err, isValidSignature) {
        if (err) {
          this.validationErrors.push(
            "invalid signature: the signature value " + this.signatureValue + " is incorrect"
          );
          callback(err);
        } else {
          callback(null, isValidSignature);
        }
      });
    }
  }

  getCanonSignedInfoXml(doc) {
    const signedInfo = utils.findChilds(this.signatureNode, "SignedInfo");
    if (signedInfo.length === 0) {
      throw new Error("could not find SignedInfo element in the message");
    }

    if (
      this.canonicalizationAlgorithm === "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" ||
      this.canonicalizationAlgorithm ===
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
    ) {
      if (!doc || typeof doc !== "object") {
        throw new Error(
          "When canonicalization method is non-exclusive, whole xml dom must be provided as an argument"
        );
      }
    }

    /**
     * Search for ancestor namespaces before canonicalization.
     */
    let ancestorNamespaces = [];
    ancestorNamespaces = utils.findAncestorNs(doc, "//*[local-name()='SignedInfo']");

    const c14nOptions = {
      ancestorNamespaces: ancestorNamespaces,
    };
    return this.getCanonXml([this.canonicalizationAlgorithm], signedInfo[0], c14nOptions);
  }

  getCanonReferenceXml(doc, ref, node) {
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

  validateSignatureValue(doc, callback) {
    const signedInfoCanon = this.getCanonSignedInfoXml(doc);
    const signer = this.findSignatureAlgorithm(this.signatureAlgorithm);
    const res = signer.verifySignature(
      signedInfoCanon,
      this.getCertFromKeyInfo(this.keyInfo) || this.publicCert || this.privateKey,
      this.signatureValue,
      callback
    );
    if (!res && !callback) {
      this.validationErrors.push(
        "invalid signature: the signature value " + this.signatureValue + " is incorrect"
      );
    }
    return res;
  }

  calculateSignatureValue(doc, callback) {
    const signedInfoCanon = this.getCanonSignedInfoXml(doc);
    const signer = this.findSignatureAlgorithm(this.signatureAlgorithm);
    this.signatureValue = signer.getSignature(signedInfoCanon, this.privateKey, callback);
  }

  findSignatureAlgorithm(name) {
    const algo = this.SignatureAlgorithms[name];
    if (algo) {
      return new algo();
    } else {
      throw new Error("signature algorithm '" + name + "' is not supported");
    }
  }

  findCanonicalizationAlgorithm(name) {
    const algo = this.CanonicalizationAlgorithms[name];
    if (algo) {
      return new algo();
    } else {
      throw new Error("canonicalization algorithm '" + name + "' is not supported");
    }
  }

  findHashAlgorithm(name) {
    const algo = this.HashAlgorithms[name];
    if (algo) {
      return new algo();
    } else {
      throw new Error("hash algorithm '" + name + "' is not supported");
    }
  }

  validateReferences(doc) {
    for (const ref of this.references) {
      let elemXpath;
      const uri = ref.uri[0] === "#" ? ref.uri.substring(1) : ref.uri;
      let elem = [];

      if (uri === "") {
        elem = xpath.select("//*", doc);
      } else if (uri.indexOf("'") !== -1) {
        // xpath injection
        throw new Error("Cannot validate a uri with quotes inside it");
      } else {
        let num_elements_for_id = 0;
        for (const attr of this.idAttributes) {
          const tmp_elemXpath = `//*[@*[local-name(.)='${attr}']='${uri}']`;
          const tmp_elem = xpath.select(tmp_elemXpath, doc);
          num_elements_for_id += tmp_elem.length;
          if (tmp_elem.length > 0) {
            elem = tmp_elem;
            elemXpath = tmp_elemXpath;
          }
        }
        if (num_elements_for_id > 1) {
          throw new Error(
            "Cannot validate a document which contains multiple elements with the " +
              "same value for the ID / Id / Id attributes, in order to prevent " +
              "signature wrapping attack."
          );
        }

        ref.xpath = elemXpath;
      }

      if (elem.length === 0) {
        this.validationErrors.push(
          "invalid signature: the signature references an element with uri " +
            ref.uri +
            " but could not find such element in the xml"
        );
        return false;
      }

      const canonXml = this.getCanonReferenceXml(doc, ref, elem[0]);

      const hash = this.findHashAlgorithm(ref.digestAlgorithm);
      const digest = hash.getHash(canonXml);

      if (!utils.validateDigestValue(digest, ref.digestValue)) {
        this.validationErrors.push(
          "invalid signature: for uri " +
            ref.uri +
            " calculated digest is " +
            digest +
            " but the xml to validate supplies digest " +
            ref.digestValue
        );

        return false;
      }
    }
    return true;
  }

  loadSignature(signatureNode) {
    if (typeof signatureNode === "string") {
      this.signatureNode = signatureNode = new Dom().parseFromString(signatureNode);
    } else {
      this.signatureNode = signatureNode;
    }

    this.signatureXml = signatureNode.toString();

    const nodes = xpath.select(
      ".//*[local-name(.)='CanonicalizationMethod']/@Algorithm",
      signatureNode
    );
    if (nodes.length === 0) {
      throw new Error("could not find CanonicalizationMethod/@Algorithm element");
    }
    this.canonicalizationAlgorithm = nodes[0].value;

    this.signatureAlgorithm = utils.findFirst(
      signatureNode,
      ".//*[local-name(.)='SignatureMethod']/@Algorithm"
    ).value;

    this.references = [];
    const references = xpath.select(
      ".//*[local-name(.)='SignedInfo']/*[local-name(.)='Reference']",
      signatureNode
    );
    if (references.length === 0) {
      throw new Error("could not find any Reference elements");
    }

    for (const reference of references) {
      this.loadReference(reference);
    }

    this.signatureValue = utils
      .findFirst(signatureNode, ".//*[local-name(.)='SignatureValue']/text()")
      .data.replace(/\r?\n/g, "");

    this.keyInfo = xpath.select(".//*[local-name(.)='KeyInfo']", signatureNode);
  }

  /**
   * Load the reference xml node to a model
   *
   */
  loadReference(ref) {
    let nodes = utils.findChilds(ref, "DigestMethod");
    if (nodes.length === 0) {
      throw new Error("could not find DigestMethod in reference " + ref.toString());
    }
    const digestAlgoNode = nodes[0];

    const attr = utils.findAttr(digestAlgoNode, "Algorithm");
    if (!attr) {
      throw new Error("could not find Algorithm attribute in node " + digestAlgoNode.toString());
    }
    const digestAlgo = attr.value;

    nodes = utils.findChilds(ref, "DigestValue");
    if (nodes.length === 0) {
      throw new Error("could not find DigestValue node in reference " + ref.toString());
    }
    if (nodes[0].childNodes.length === 0 || !nodes[0].firstChild.data) {
      throw new Error("could not find the value of DigestValue in " + nodes[0].toString());
    }
    const digestValue = nodes[0].firstChild.data;

    const transforms = [];
    let trans;
    let inclusiveNamespacesPrefixList;
    nodes = utils.findChilds(ref, "Transforms");
    if (nodes.length !== 0) {
      const transformsNode = nodes[0];
      const transformsAll = utils.findChilds(transformsNode, "Transform");
      for (const t of transformsAll) {
        trans = t;
        transforms.push(utils.findAttr(trans, "Algorithm").value);
      }

      // This is a little strange, we are looking for children of the last child of `transformsNode`
      const inclusiveNamespaces = utils.findChilds(trans, "InclusiveNamespaces");
      if (inclusiveNamespaces.length > 0) {
        //Should really only be one prefix list, but maybe there's some circumstances where more than one to lets handle it
        for (let i = 0; i < inclusiveNamespaces.length; i++) {
          if (inclusiveNamespacesPrefixList) {
            inclusiveNamespacesPrefixList =
              inclusiveNamespacesPrefixList +
              " " +
              inclusiveNamespaces[i].getAttribute("PrefixList");
          } else {
            inclusiveNamespacesPrefixList = inclusiveNamespaces[i].getAttribute("PrefixList");
          }
        }
      }
    }

    const hasImplicitTransforms =
      Array.isArray(this.implicitTransforms) && this.implicitTransforms.length > 0;
    if (hasImplicitTransforms) {
      this.implicitTransforms.forEach(function (t) {
        transforms.push(t);
      });
    }

    /**
     * DigestMethods take an octet stream rather than a node set. If the output of the last transform is a node set, we
     * need to canonicalize the node set to an octet stream using non-exclusive canonicalization. If there are no
     * transforms, we need to canonicalize because URI dereferencing for a same-document reference will return a node-set.
     * See:
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

    this.addReference(
      null,
      transforms,
      digestAlgo,
      utils.findAttr(ref, "URI").value,
      digestValue,
      inclusiveNamespacesPrefixList,
      false
    );
  }

  addReference(
    xpath,
    transforms,
    digestAlgorithm,
    uri,
    digestValue,
    inclusiveNamespacesPrefixList,
    isEmptyUri
  ) {
    this.references.push({
      xpath: xpath,
      transforms: transforms ? transforms : ["http://www.w3.org/2001/10/xml-exc-c14n#"],
      digestAlgorithm: digestAlgorithm ? digestAlgorithm : "http://www.w3.org/2000/09/xmldsig#sha1",
      uri: uri,
      digestValue: digestValue,
      inclusiveNamespacesPrefixList: inclusiveNamespacesPrefixList,
      isEmptyUri: isEmptyUri,
    });
  }

  /**
   * Compute the signature of the given xml (using the already defined settings)
   *
   * Options:
   *
   * - `prefix` {String} Adds a prefix for the generated signature tags
   * - `attrs` {Object} A hash of attributes and values `attrName: value` to add to the signature root node
   * - `location` {{ reference: String, action: String }}
   * - `existingPrefixes` {Object} A hash of prefixes and namespaces `prefix: namespace` already in the xml
   *   An object with a `reference` key which should
   *   contain a XPath expression, an `action` key which
   *   should contain one of the following values:
   *   `append`, `prepend`, `before`, `after`
   *
   */
  computeSignature(xml, opts, callback) {
    if (typeof opts === "function" && callback == null) {
      callback = opts;
    }

    if (callback != null && typeof callback !== "function") {
      throw new Error("Last parameter must be a callback function");
    }

    const doc = new Dom().parseFromString(xml);
    let xmlNsAttr = "xmlns";
    const signatureAttrs = [];
    let currentPrefix;

    const validActions = ["append", "prepend", "before", "after"];

    opts = opts || {};
    const prefix = opts.prefix;
    const attrs = opts.attrs || {};
    const location = opts.location || {};
    const existingPrefixes = opts.existingPrefixes || {};

    this.namespaceResolver = {
      lookupNamespaceURI: function (prefix) {
        return existingPrefixes[prefix];
      },
    };

    // defaults to the root node
    location.reference = location.reference || "/*";
    // defaults to append action
    location.action = location.action || "append";

    if (validActions.indexOf(location.action) === -1) {
      const err = new Error(
        "location.action option has an invalid action: " +
          location.action +
          ", must be any of the following values: " +
          validActions.join(", ")
      );
      if (!callback) {
        throw err;
      } else {
        callback(err, null);
        return;
      }
    }

    // automatic insertion of `:`
    if (prefix) {
      xmlNsAttr += ":" + prefix;
      currentPrefix = prefix + ":";
    } else {
      currentPrefix = "";
    }

    Object.keys(attrs).forEach(function (name) {
      if (name !== "xmlns" && name !== xmlNsAttr) {
        signatureAttrs.push(name + '="' + attrs[name] + '"');
      }
    });

    // add the xml namespace attribute
    signatureAttrs.push(xmlNsAttr + '="http://www.w3.org/2000/09/xmldsig#"');

    let signatureXml = "<" + currentPrefix + "Signature " + signatureAttrs.join(" ") + ">";

    signatureXml += this.createSignedInfo(doc, prefix);
    signatureXml += this.getKeyInfo(prefix);
    signatureXml += "</" + currentPrefix + "Signature>";

    this.originalXmlWithIds = doc.toString();

    let existingPrefixesString = "";
    Object.keys(existingPrefixes).forEach(function (key) {
      existingPrefixesString += "xmlns:" + key + '="' + existingPrefixes[key] + '" ';
    });

    // A trick to remove the namespaces that already exist in the xml
    // This only works if the prefix and namespace match with those in te xml
    const dummySignatureWrapper =
      "<Dummy " + existingPrefixesString + ">" + signatureXml + "</Dummy>";
    const nodeXml = new Dom().parseFromString(dummySignatureWrapper);
    const signatureDoc = nodeXml.documentElement.firstChild;

    let referenceNode = xpath.select(location.reference, doc);

    if (!referenceNode || referenceNode.length === 0) {
      const err2 = new Error(
        "the following xpath cannot be used because it was not found: " + location.reference
      );
      if (!callback) {
        throw err2;
      } else {
        callback(err2, null);
        return;
      }
    }

    referenceNode = referenceNode[0];

    if (location.action === "append") {
      referenceNode.appendChild(signatureDoc);
    } else if (location.action === "prepend") {
      referenceNode.insertBefore(signatureDoc, referenceNode.firstChild);
    } else if (location.action === "before") {
      referenceNode.parentNode.insertBefore(signatureDoc, referenceNode);
    } else if (location.action === "after") {
      referenceNode.parentNode.insertBefore(signatureDoc, referenceNode.nextSibling);
    }

    this.signatureNode = signatureDoc;
    let signedInfoNode = utils.findChilds(this.signatureNode, "SignedInfo");
    if (signedInfoNode.length === 0) {
      const err3 = new Error("could not find SignedInfo element in the message");
      if (!callback) {
        throw err3;
      } else {
        callback(err3);
        return;
      }
    }
    signedInfoNode = signedInfoNode[0];

    if (!callback) {
      //Synchronous flow
      this.calculateSignatureValue(doc);
      signatureDoc.insertBefore(this.createSignature(prefix), signedInfoNode.nextSibling);
      this.signatureXml = signatureDoc.toString();
      this.signedXml = doc.toString();
    } else {
      const self = this;
      //Asynchronous flow
      this.calculateSignatureValue(doc, function (err, signature) {
        if (err) {
          callback(err);
        } else {
          self.signatureValue = signature;
          signatureDoc.insertBefore(self.createSignature(prefix), signedInfoNode.nextSibling);
          self.signatureXml = signatureDoc.toString();
          self.signedXml = doc.toString();
          callback(null, self);
        }
      });
    }
  }

  getKeyInfo(prefix) {
    let res = "";
    let currentPrefix;

    currentPrefix = prefix || "";
    currentPrefix = currentPrefix ? currentPrefix + ":" : currentPrefix;

    let keyInfoAttrs = "";
    if (this.keyInfoAttributes) {
      Object.keys(this.keyInfoAttributes).forEach((name) => {
        keyInfoAttrs += " " + name + '="' + this.keyInfoAttributes[name] + '"';
      });
    }
    const keyInfoContent = this.getKeyInfoContent({ publicCert: this.publicCert, prefix });
    if (keyInfoAttrs !== "" || keyInfoContent != null) {
      res += "<" + currentPrefix + "KeyInfo" + keyInfoAttrs + ">";
      res += keyInfoContent;
      res += "</" + currentPrefix + "KeyInfo>";
      return res;
    } else {
      return "";
    }
  }

  /**
   * Generate the Reference nodes (as part of the signature process)
   *
   */
  createReferences(doc, prefix) {
    let res = "";

    prefix = prefix || "";
    prefix = prefix ? prefix + ":" : prefix;

    for (const ref of this.references) {
      const nodes = xpath.selectWithResolver(ref.xpath, doc, this.namespaceResolver);

      if (nodes.length === 0) {
        throw new Error(
          "the following xpath cannot be signed because it was not found: " + ref.xpath
        );
      }

      for (const node of nodes) {
        if (ref.isEmptyUri) {
          res += "<" + prefix + 'Reference URI="">';
        } else {
          const id = this.ensureHasId(node);
          ref.uri = id;
          res += "<" + prefix + 'Reference URI="#' + id + '">';
        }
        res += "<" + prefix + "Transforms>";
        for (const trans of ref.transforms) {
          const transform = this.findCanonicalizationAlgorithm(trans);
          res += "<" + prefix + 'Transform Algorithm="' + transform.getAlgorithmName() + '"';
          if (ref.inclusiveNamespacesPrefixList) {
            res += ">";
            res +=
              '<InclusiveNamespaces PrefixList="' +
              ref.inclusiveNamespacesPrefixList +
              '" xmlns="' +
              transform.getAlgorithmName() +
              '"/>';
            res += "</" + prefix + "Transform>";
          } else {
            res += " />";
          }
        }

        const canonXml = this.getCanonReferenceXml(doc, ref, node);

        const digestAlgorithm = this.findHashAlgorithm(ref.digestAlgorithm);
        res +=
          "</" +
          prefix +
          "Transforms>" +
          "<" +
          prefix +
          'DigestMethod Algorithm="' +
          digestAlgorithm.getAlgorithmName() +
          '" />' +
          "<" +
          prefix +
          "DigestValue>" +
          digestAlgorithm.getHash(canonXml) +
          "</" +
          prefix +
          "DigestValue>" +
          "</" +
          prefix +
          "Reference>";
      }
    }

    return res;
  }

  getCanonXml(transforms, node, options) {
    options = options || {};
    options.defaultNsForPrefix = options.defaultNsForPrefix || SignedXml.defaultNsForPrefix;
    options.signatureNode = this.signatureNode;

    let canonXml = node.cloneNode(true); // Deep clone

    Object.values(transforms).forEach((transformName) => {
      const transform = this.findCanonicalizationAlgorithm(transformName);
      canonXml = transform.process(canonXml, options);
      //TODO: currently transform.process may return either Node or String value (enveloped transformation returns Node, exclusive-canonicalization returns String).
      //This either needs to be more explicit in the API, or all should return the same.
      //exclusive-canonicalization returns String since it builds the Xml by hand. If it had used xmldom it would incorrectly minimize empty tags
      //to <x/> instead of <x></x> and also incorrectly handle some delicate line break issues.
      //enveloped transformation returns Node since if it would return String consider this case:
      //<x xmlns:p='ns'><p:y/></x>
      //if only y is the node to sign then a string would be <p:y/> without the definition of the p namespace. probably xmldom toString() should have added it.
    });

    return canonXml.toString();
  }

  /**
   * Ensure an element has Id attribute. If not create it with unique value.
   * Work with both normal and wssecurity Id flavour
   */
  ensureHasId(node) {
    let attr;

    if (this.idMode === "wssecurity") {
      attr = utils.findAttr(
        node,
        "Id",
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
      );
    } else {
      Object.values(this.idAttributes).some((idAttribute) => {
        attr = utils.findAttr(node, idAttribute, null);
        return !!attr; // This will break the loop as soon as a truthy attr is found.
      });
    }

    if (attr) {
      return attr.value;
    }

    //add the attribute
    const id = "_" + this.id++;

    if (this.idMode === "wssecurity") {
      node.setAttributeNS(
        "http://www.w3.org/2000/xmlns/",
        "xmlns:wsu",
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
      );
      node.setAttributeNS(
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
        "wsu:Id",
        id
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
  createSignedInfo(doc, prefix) {
    const transform = this.findCanonicalizationAlgorithm(this.canonicalizationAlgorithm);
    const algo = this.findSignatureAlgorithm(this.signatureAlgorithm);
    let currentPrefix;

    currentPrefix = prefix || "";
    currentPrefix = currentPrefix ? currentPrefix + ":" : currentPrefix;

    let res = "<" + currentPrefix + "SignedInfo>";
    res +=
      "<" +
      currentPrefix +
      'CanonicalizationMethod Algorithm="' +
      transform.getAlgorithmName() +
      '"';
    if (this.inclusiveNamespacesPrefixList) {
      res += ">";
      res +=
        '<InclusiveNamespaces PrefixList="' +
        this.inclusiveNamespacesPrefixList +
        '" xmlns="' +
        transform.getAlgorithmName() +
        '"/>';
      res += "</" + currentPrefix + "CanonicalizationMethod>";
    } else {
      res += " />";
    }
    res += "<" + currentPrefix + 'SignatureMethod Algorithm="' + algo.getAlgorithmName() + '" />';

    res += this.createReferences(doc, prefix);
    res += "</" + currentPrefix + "SignedInfo>";
    return res;
  }

  /**
   * Create the Signature element
   *
   */
  createSignature(prefix) {
    let xmlNsAttr = "xmlns";

    if (prefix) {
      xmlNsAttr += ":" + prefix;
      prefix += ":";
    } else {
      prefix = "";
    }

    const signatureValueXml =
      "<" + prefix + "SignatureValue>" + this.signatureValue + "</" + prefix + "SignatureValue>";
    //the canonicalization requires to get a valid xml node.
    //we need to wrap the info in a dummy signature since it contains the default namespace.
    const dummySignatureWrapper =
      "<" +
      prefix +
      "Signature " +
      xmlNsAttr +
      '="http://www.w3.org/2000/09/xmldsig#">' +
      signatureValueXml +
      "</" +
      prefix +
      "Signature>";

    const doc = new Dom().parseFromString(dummySignatureWrapper);
    return doc.documentElement.firstChild;
  }

  getSignatureXml() {
    return this.signatureXml;
  }

  getOriginalXmlWithIds() {
    return this.originalXmlWithIds;
  }

  getSignedXml() {
    return this.signedXml;
  }
}

SignedXml.defaultNsForPrefix = {
  ds: "http://www.w3.org/2000/09/xmldsig#",
};

exports.SignedXml = SignedXml;

module.exports = {
  SignedXml,
};
