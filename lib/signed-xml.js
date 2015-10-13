var select = require('xpath.js')
  , Dom = require('xmldom').DOMParser
  , utils = require('./utils')
  , ExclusiveCanonicalization = require('./exclusive-canonicalization').ExclusiveCanonicalization
  , ExclusiveCanonicalizationWithComments = require('./exclusive-canonicalization').ExclusiveCanonicalizationWithComments
  , EnvelopedSignature = require('./enveloped-signature').EnvelopedSignature
  , crypto = require('crypto')
  , fs = require('fs')

exports.SignedXml = SignedXml
exports.FileKeyInfo = FileKeyInfo

/**
 * A key info provider implementation
 *
 */
function FileKeyInfo(file) {
  this.file = file

  this.getKeyInfo = function(key, prefix) {
	prefix = prefix || ''
	prefix = prefix ? prefix + ':' : prefix
    return "<" + prefix + "X509Data></" + prefix + "X509Data>"
  }

  this.getKey = function(keyInfo) {
    return fs.readFileSync(this.file)
  }
}

/**
 * Hash algorithm implementation
 *
 */
function SHA1() {

  this.getHash = function(xml) {
    var shasum = crypto.createHash('sha1')
    shasum.update(xml, 'utf8')
    var res = shasum.digest('base64')
    return res
  }

  this.getAlgorithmName = function() {
    return "http://www.w3.org/2000/09/xmldsig#sha1"
  }
}

function SHA256() {

  this.getHash = function(xml) {
    var shasum = crypto.createHash('sha256')
    shasum.update(xml, 'utf8')
    var res = shasum.digest('base64')
    return res
  }

  this.getAlgorithmName = function() {
    return "http://www.w3.org/2001/04/xmlenc#sha256"
  }
}

function SHA512() {

  this.getHash = function(xml) {
    var shasum = crypto.createHash('sha512')
    shasum.update(xml, 'utf8')
    var res = shasum.digest('base64')
    return res
  }

  this.getAlgorithmName = function() {
    return "http://www.w3.org/2001/04/xmlenc#sha512"
  }
}


/**
 * Signature algorithm implementation
 *
 */
function RSASHA1() {

  /**
  * Sign the given string using the given key
  *
  */
  this.getSignature = function(signedInfo, signingKey) {
    var signer = crypto.createSign("RSA-SHA1")
    signer.update(signedInfo)
    var res = signer.sign(signingKey, 'base64')
    return res
  }

  /**
  * Verify the given signature of the given string using key
  *
  */
  this.verifySignature = function(str, key, signatureValue) {
    var verifier = crypto.createVerify("RSA-SHA1")
    verifier.update(str)
    var res = verifier.verify(key, signatureValue, 'base64')
    return res
  }

  this.getAlgorithmName = function() {
    return "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
  }

}


/**
 * Signature algorithm implementation
 *
 */
function RSASHA256() {

  /**
  * Sign the given string using the given key
  *
  */
  this.getSignature = function(signedInfo, signingKey) {
    var signer = crypto.createSign("RSA-SHA256")
    signer.update(signedInfo)
    var res = signer.sign(signingKey, 'base64')
    return res
  }

  /**
  * Verify the given signature of the given string using key
  *
  */
  this.verifySignature = function(str, key, signatureValue) {
    var verifier = crypto.createVerify("RSA-SHA256")
    verifier.update(str)
    var res = verifier.verify(key, signatureValue, 'base64')
    return res
  }

  this.getAlgorithmName = function() {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
  }

}

/**
 * Signature algorithm implementation
 *
 */
function RSASHA512() {

  /**
  * Sign the given string using the given key
  *
  */
  this.getSignature = function(signedInfo, signingKey) {
    var signer = crypto.createSign("RSA-SHA512")
    signer.update(signedInfo)
    var res = signer.sign(signingKey, 'base64')
    return res
  }

  /**
  * Verify the given signature of the given string using key
  *
  */
  this.verifySignature = function(str, key, signatureValue) {
    var verifier = crypto.createVerify("RSA-SHA512")
    verifier.update(str)
    var res = verifier.verify(key, signatureValue, 'base64')
    return res
  }

  this.getAlgorithmName = function() {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
  }
}

function HMACSHA1() {
    this.verifySignature = function(str, key, signatureValue) {
        var verifier = crypto.createHmac("SHA1", key);
        verifier.update(str);
        var res = verifier.digest('base64');
        return res === signatureValue;
    };

    this.getAlgorithmName = function() {
        return "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
    };

    this.getSignature = function(signedInfo, signingKey) {
        var verifier = crypto.createHmac("SHA1", signingKey);
        verifier.update(signedInfo);
        var res = verifier.digest('base64');
        return res;
    };
}

/**
* Xml signature implementation
*
* @param {string} idMode. Value of "wssecurity" will create/validate id's with the ws-security namespace
*/
function SignedXml(idMode, options) {
  this.options = options || {};
  this.idMode = idMode
  this.references = []
  this.id = 0
  this.signingKey = null
  this.signatureAlgorithm = this.options.signatureAlgorithm || "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  this.keyInfoProvider = null
  this.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#"
  this.signedXml = ""
  this.signatureXml = ""
  this.signatureNode = null
  this.signatureValue = ""
  this.originalXmlWithIds = ""
  this.validationErrors = []
  this.keyInfo = null
  this.idAttributes = [ 'Id', 'ID' ];
  if (this.options.idAttribute) this.idAttributes.splice(0, 0, this.options.idAttribute);
}

SignedXml.CanonicalizationAlgorithms = {
  'http://www.w3.org/2001/10/xml-exc-c14n#': ExclusiveCanonicalization,
  'http://www.w3.org/2001/10/xml-exc-c14n#WithComments': ExclusiveCanonicalizationWithComments,
  'http://www.w3.org/2000/09/xmldsig#enveloped-signature': EnvelopedSignature
}

SignedXml.HashAlgorithms = {
  'http://www.w3.org/2000/09/xmldsig#sha1': SHA1,
  'http://www.w3.org/2001/04/xmlenc#sha256': SHA256,
  'http://www.w3.org/2001/04/xmlenc#sha512': SHA512
}

SignedXml.SignatureAlgorithms = {
  'http://www.w3.org/2000/09/xmldsig#rsa-sha1': RSASHA1,
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': RSASHA256,
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': RSASHA512,
  'http://www.w3.org/2000/09/xmldsig#hmac-sha1': HMACSHA1
}

SignedXml.prototype.checkSignature = function(xml) {
  this.validationErrors = []
  this.signedXml = xml

  if (!this.keyInfoProvider) {
    throw new Error("cannot validate signature since no key info resolver was provided")
  }

  this.signingKey = this.keyInfoProvider.getKey(this.keyInfo)
  if (!this.signingKey) throw new Error("key info provider could not resolve key info " + this.keyInfo)

  var doc = new Dom().parseFromString(xml)

  if (!this.validateReferences(doc)) {
    return false;
  }

  if (!this.validateSignatureValue()) {
    return false;
  }

  return true
}

SignedXml.prototype.validateSignatureValue = function() {
  var signedInfo = utils.findChilds(this.signatureNode, "SignedInfo")
  if (signedInfo.length==0) throw new Error("could not find SignedInfo element in the message")
  var signedInfoCanon = this.getCanonXml([this.canonicalizationAlgorithm], signedInfo[0])
  var signer = this.findSignatureAlgorithm(this.signatureAlgorithm)
  var res = signer.verifySignature(signedInfoCanon, this.signingKey, this.signatureValue)
  if (!res) this.validationErrors.push("invalid signature: the signature value " +
                                        this.signatureValue + " is incorrect")
  return res
}

SignedXml.prototype.findSignatureAlgorithm = function(name) {
  var algo = SignedXml.SignatureAlgorithms[name]
  if (algo) return new algo()
  else throw new Error("signature algorithm '" + name + "' is not supported");
}

SignedXml.prototype.findCanonicalizationAlgorithm = function(name) {
  var algo = SignedXml.CanonicalizationAlgorithms[name]
  if (algo) return new algo()
  else throw new Error("canonicalization algorithm '" + name + "' is not supported");
}

SignedXml.prototype.findHashAlgorithm = function(name) {
  var algo = SignedXml.HashAlgorithms[name]
  if (algo) return new algo()
  else throw new Error("hash algorithm '" + name + "' is not supported");
}


SignedXml.prototype.validateReferences = function(doc) {
  for (var r in this.references) {
    if (!this.references.hasOwnProperty(r)) continue;

    var ref = this.references[r]

    var uri = ref.uri[0]=="#" ? ref.uri.substring(1) : ref.uri
    var elem = [];

    if (uri=="") {
      elem = select(doc, "//*")
    }
    else {
      for (var index in this.idAttributes) {
        if (!this.idAttributes.hasOwnProperty(index)) continue;

        elem = select(doc, "//*[@*[local-name(.)='" + this.idAttributes[index] + "']='" + uri + "']")
        if (elem.length > 0) break;
      }
    }

    if (elem.length==0) {
      this.validationErrors.push("invalid signature: the signature refernces an element with uri "+
                        ref.uri + " but could not find such element in the xml")
      return false
    }
    var canonXml = this.getCanonXml(ref.transforms, elem[0], { inclusiveNamespacesPrefixList: ref.inclusiveNamespacesPrefixList });

    var hash = this.findHashAlgorithm(ref.digestAlgorithm)
    var digest = hash.getHash(canonXml)

    if (digest!=ref.digestValue) {
      this.validationErrors.push("invalid signature: for uri " + ref.uri +
                                " calculated digest is "  + digest +
                                " but the xml to validate supplies digest " + ref.digestValue)

      return false
    }
  }
  return true
}

SignedXml.prototype.loadSignature = function(signatureNode) {
  if (typeof signatureNode === 'string') {
    this.signatureNode = signatureNode = new Dom().parseFromString(signatureNode);
  } else {
    this.signatureNode = signatureNode;
  }

  this.signatureXml = signatureNode.toString();

  var nodes = select(signatureNode, ".//*[local-name(.)='CanonicalizationMethod']/@Algorithm")
  if (nodes.length==0) throw new Error("could not find CanonicalizationMethod/@Algorithm element")
  this.canonicalizationAlgorithm = nodes[0].value

  this.signatureAlgorithm =
    utils.findFirst(signatureNode, ".//*[local-name(.)='SignatureMethod']/@Algorithm").value

  this.references = []
  var references = select(signatureNode, ".//*[local-name(.)='SignedInfo']/*[local-name(.)='Reference']")
  if (references.length == 0) throw new Error("could not find any Reference elements")

  for (var i in references) {
    if (!references.hasOwnProperty(i)) continue;

    this.loadReference(references[i])
  }

  this.signatureValue =
    utils.findFirst(signatureNode, ".//*[local-name(.)='SignatureValue']/text()").data.replace(/\n/g, '')

  this.keyInfo = select(signatureNode, ".//*[local-name(.)='KeyInfo']")
}

/**
 * Load the reference xml node to a model
 *
 */
SignedXml.prototype.loadReference = function(ref) {
  var nodes = utils.findChilds(ref, "DigestMethod")
  if (nodes.length==0) throw new Error("could not find DigestMethod in reference " + ref.toString())
  var digestAlgoNode = nodes[0]

  var attr = utils.findAttr(digestAlgoNode, "Algorithm")
  if (!attr) throw new Error("could not find Algorithm attribute in node " + digestAlgoNode.toString())
  var digestAlgo = attr.value

  nodes = utils.findChilds(ref, "DigestValue")
  if (nodes.length==0) throw new Error("could not find DigestValue node in reference " + ref.toString())
  if (nodes[0].childNodes.length==0 || !nodes[0].firstChild.data)
  {
    throw new Error("could not find the value of DigestValue in " + nodes[0].toString())
  }
  var digestValue = nodes[0].firstChild.data

  var transforms = []
  var inclusiveNamespacesPrefixList;
  nodes = utils.findChilds(ref, "Transforms")
  if (nodes.length!=0) {
    var transformsNode = nodes[0]
    var transformsAll = utils.findChilds(transformsNode, "Transform")
    for (var t in transformsAll) {
      if (!transformsAll.hasOwnProperty(t)) continue;

      var trans = transformsAll[t]
      transforms.push(utils.findAttr(trans, "Algorithm").value)
    }

    var inclusiveNamespaces = select(transformsNode, "//*[local-name(.)='InclusiveNamespaces']");
    if (inclusiveNamespaces.length > 0) {
      inclusiveNamespacesPrefixList = inclusiveNamespaces[0].getAttribute('PrefixList');
    }
  }

  //***workaround for validating windows mobile store signatures - it uses c14n but does not state it in the transforms
  if (transforms.length==1 && transforms[0]=="http://www.w3.org/2000/09/xmldsig#enveloped-signature")
    transforms.push("http://www.w3.org/2001/10/xml-exc-c14n#")

  this.addReference(null, transforms, digestAlgo, utils.findAttr(ref, "URI").value, digestValue, inclusiveNamespacesPrefixList, false)
}

SignedXml.prototype.addReference = function(xpath, transforms, digestAlgorithm, uri, digestValue, inclusiveNamespacesPrefixList, isEmptyUri) {
  this.references.push({
    "xpath": xpath,
    "transforms": transforms ? transforms : ["http://www.w3.org/2001/10/xml-exc-c14n#"] ,
    "digestAlgorithm": digestAlgorithm ? digestAlgorithm : "http://www.w3.org/2000/09/xmldsig#sha1",
    "uri": uri,
    "digestValue": digestValue,
    "inclusiveNamespacesPrefixList": inclusiveNamespacesPrefixList,
    "isEmptyUri": isEmptyUri
  });
}

/**
 * Compute the signature of the given xml (usign the already defined settings)
 *
 * Options:
 *
 * - `prefix` {String} Adds a prefix for the generated signature tags
 * - `attrs` {Object} A hash of attributes and values `attrName: value` to add to the signature root node
 * - `location` {{ reference: String, action: String }}
 *   An object with a `reference` key which should
 *   contain a XPath expression, an `action` key which
 *   should contain one of the following values:
 *   `append`, `prepend`, `before`, `after`
 *
 */
SignedXml.prototype.computeSignature = function(xml, opts) {
  var doc = new Dom().parseFromString(xml),
      xmlNsAttr = "xmlns",
      signatureAttrs = [],
      location,
      attrs,
      prefix,
      currentPrefix;

  var validActions = ["append", "prepend", "before", "after"];

  opts = opts || {};
  prefix = opts.prefix;
  attrs = opts.attrs || {};
  location = opts.location || {};
  // defaults to the root node
  location.reference = location.reference || "/*";
  // defaults to append action
  location.action = location.action || "append";

  if (validActions.indexOf(location.action) === -1) {
    throw new Error("location.action option has an invalid action: " + location.action +
                    ", must be any of the following values: " + validActions.join(", "));
  }

  // automatic insertion of `:`
  if (prefix) {
    xmlNsAttr += ":" + prefix;
    currentPrefix = prefix + ":";
  } else {
    currentPrefix = "";
  }

  Object.keys(attrs).forEach(function(name) {
    if (name !== "xmlns" && name !== xmlNsAttr) {
      signatureAttrs.push(name + "=\"" + attrs[name] + "\"");
    }
  });

  // add the xml namespace attribute
  signatureAttrs.push(xmlNsAttr + "=\"http://www.w3.org/2000/09/xmldsig#\"");

  this.signatureXml = "<" + currentPrefix + "Signature " + signatureAttrs.join(" ") + ">"

  var signedInfo = this.createSignedInfo(doc, prefix);
  this.signatureXml += signedInfo;
  this.signatureXml += this.createSignature(signedInfo, prefix);
  this.signatureXml += this.getKeyInfo(prefix)
  this.signatureXml += "</" + currentPrefix + "Signature>"

  this.originalXmlWithIds = doc.toString()

  var signatureDoc = new Dom().parseFromString(this.signatureXml)

  var referenceNode = select(doc, location.reference);

  if (!referenceNode || referenceNode.length === 0) {
    throw new Error("the following xpath cannot be used because it was not found: " + location.reference);
  }

  referenceNode = referenceNode[0];

  if (location.action === "append") {
    referenceNode.appendChild(signatureDoc.documentElement);
  } else if (location.action === "prepend") {
    referenceNode.insertBefore(signatureDoc.documentElement, referenceNode.firstChild);
  } else if (location.action === "before") {
    referenceNode.parentNode.insertBefore(signatureDoc.documentElement, referenceNode);
  } else if (location.action === "after") {
    referenceNode.parentNode.insertBefore(signatureDoc.documentElement, referenceNode.nextSibling);
  }

  this.signedXml = doc.toString()
}

SignedXml.prototype.getKeyInfo = function(prefix) {
  var res = ""
  var currentPrefix

  currentPrefix = prefix || ''
  currentPrefix = currentPrefix ? currentPrefix + ':' : currentPrefix

  if (this.keyInfoProvider) {
    res += "<" + currentPrefix + "KeyInfo>"
    res += this.keyInfoProvider.getKeyInfo(this.signingKey, prefix)
    res += "</" + currentPrefix + "KeyInfo>"
  }
  return res
}

/**
 * Generate the Reference nodes (as part of the signature process)
 *
 */
SignedXml.prototype.createReferences = function(doc, prefix) {

  var res = ""

  prefix = prefix || ''
  prefix = prefix ? prefix + ':' : prefix

  for (var n in this.references) {
    if (!this.references.hasOwnProperty(n)) continue;

    var ref = this.references[n]
      , nodes = select(doc, ref.xpath)

    if (nodes.length==0) {
      throw new Error('the following xpath cannot be signed because it was not found: ' + ref.xpath)
    }

    for (var h in nodes) {
      if (!nodes.hasOwnProperty(h)) continue;

      var node = nodes[h]
      if (ref.isEmptyUri) {
        res += "<" + prefix + "Reference URI=\"\">"
      }
      else {
        var id = this.ensureHasId(node);
        ref.uri = id
        res += "<" + prefix + "Reference URI=\"#" + id + "\">"
      }
      res += "<" + prefix + "Transforms>"
      for (var t in ref.transforms) {
        if (!ref.transforms.hasOwnProperty(t)) continue;

        var trans = ref.transforms[t]
        var transform = this.findCanonicalizationAlgorithm(trans)
        res += "<" + prefix + "Transform Algorithm=\"" + transform.getAlgorithmName() + "\" />"
      }

      var canonXml = this.getCanonXml(ref.transforms, node)

      var digestAlgorithm = this.findHashAlgorithm(ref.digestAlgorithm)
      res += "</" + prefix + "Transforms>"+
             "<" + prefix + "DigestMethod Algorithm=\"" + digestAlgorithm.getAlgorithmName() + "\" />"+
              "<" + prefix + "DigestValue>" + digestAlgorithm.getHash(canonXml) + "</" + prefix + "DigestValue>"+
              "</" + prefix + "Reference>"
    }
  }

  return res
}

SignedXml.prototype.getCanonXml = function(transforms, node, options) {
  var canonXml = node
  for (var t in transforms) {
    if (!transforms.hasOwnProperty(t)) continue;

    var transform = this.findCanonicalizationAlgorithm(transforms[t])
    canonXml = transform.process(canonXml, options);
    //TODO: currently transform.process may return either Node or String value (enveloped transformation returns Node, exclusive-canonicalization returns String).
    //This eitehr needs to be more explicit in the API, or all should return the same.
    //exclusive-canonicalization returns String since it builds the Xml by hand. If it had used xmldom it would inccorectly minimize empty tags
    //to <x/> instead of <x></x> and also incorrectly handle some delicate line break issues.
    //enveloped transformation returns Node since if it would return String consider this case:
    //<x xmlns:p='ns'><p:y/></x>
    //if only y is the node to sign then a string would be <p:y/> without the definition of the p namespace. probably xmldom toString() should have added it.
  }
  return canonXml.toString()
}

/**
 * Ensure an element has Id attribute. If not create it with unique value.
 * Work with both normal and wssecurity Id flavour
 */
SignedXml.prototype.ensureHasId = function(node) {
  var attr

  if (this.idMode=="wssecurity") {
    attr = utils.findAttr(node,
      "Id",
      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
  }
  else {
    for (var index in this.idAttributes) {
      if (!this.idAttributes.hasOwnProperty(index)) continue;

      attr = utils.findAttr(node, this.idAttributes[index], null);
      if (attr) break;
    }
  }

  if (attr) return attr.value

  //add the attribute
  var id = "_" + this.id++

  if (this.idMode=="wssecurity") {
    node.setAttributeNS("http://www.w3.org/2000/xmlns/",
      "xmlns:wsu",
      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
    node.setAttributeNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
      "wsu:Id",
      id)
  }
  else {
   node.setAttribute("Id", id)
  }

  return id
}

/**
 * Create the SignedInfo element
 *
 */
SignedXml.prototype.createSignedInfo = function(doc, prefix) {
  var transform = this.findCanonicalizationAlgorithm(this.canonicalizationAlgorithm)
  var algo = this.findSignatureAlgorithm(this.signatureAlgorithm)
  var currentPrefix

  currentPrefix = prefix || ''
  currentPrefix = currentPrefix ? currentPrefix + ':' : currentPrefix

  var res = "<" + currentPrefix + "SignedInfo>"
  res += "<" + currentPrefix + "CanonicalizationMethod Algorithm=\"" + transform.getAlgorithmName() + "\" />" +
          "<" + currentPrefix + "SignatureMethod Algorithm=\"" + algo.getAlgorithmName() + "\" />"

  res += this.createReferences(doc, prefix)
  res += "</" + currentPrefix + "SignedInfo>"
  return res
}

/**
 * Create the Signature element
 *
 */
SignedXml.prototype.createSignature = function(signedInfo, prefix) {
  var xmlNsAttr = 'xmlns'

  if (prefix) {
	xmlNsAttr += ':' + prefix;
	prefix += ':';
  } else {
	prefix = '';
  }

  //the canonicalization requires to get a valid xml node.
  //we need to wrap the info in a dummy signature since it contains the default namespace.
  var dummySignatureWrapper = "<" + prefix + "Signature " + xmlNsAttr + "=\"http://www.w3.org/2000/09/xmldsig#\">" +
                        signedInfo +
                        "</" + prefix + "Signature>"

  var xml = new Dom().parseFromString(dummySignatureWrapper)
  //get the signedInfo
  var node = xml.documentElement.firstChild;
  var canAlgorithm = new this.findCanonicalizationAlgorithm(this.canonicalizationAlgorithm)
  var canonizedSignedInfo = canAlgorithm.process(node)
  var signatureAlgorithm = this.findSignatureAlgorithm(this.signatureAlgorithm)
  this.signatureValue = signatureAlgorithm.getSignature(canonizedSignedInfo, this.signingKey)
  return "<" + prefix + "SignatureValue>" + this.signatureValue + "</" + prefix + "SignatureValue>"
}


SignedXml.prototype.getSignatureXml = function() {
  return this.signatureXml
}

SignedXml.prototype.getOriginalXmlWithIds = function() {
  return this.originalXmlWithIds
}

SignedXml.prototype.getSignedXml = function() {
  return this.signedXml
}
