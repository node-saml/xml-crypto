var select = require('./xpath.js').SelectNodes
  , Dom = require('xmldom').DOMParser
  , utils = require('./utils')
  , ExclusiveCanonicalization = require('./exclusive-canonicalization').ExclusiveCanonicalization
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

  this.getKeyInfo = function(key) {
    return "<X509Data></X509Data>"
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
    shasum.update(xml)
    var res = shasum.digest('base64')
    //console.log("hash for " + xml + "is " + res)
    return res
  }

  this.getAlgorithmName = function() {
    return "http://www.w3.org/2000/09/xmldsig#sha1"
  }
}

function SHA256() {
  
  this.getHash = function(xml) {    
    var shasum = crypto.createHash('sha256')
    shasum.update(xml)
    var res = shasum.digest('base64')
    //console.log("hash for " + xml + "is " + res)
    return res
  }

  this.getAlgorithmName = function() {
    return "http://www.w3.org/2001/04/xmlenc#sha256"
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
  this.signatureXmlDoc = null
  this.signatureValue = ""
  this.originalXmlWithIds = ""
  this.validationErrors = []
  this.keyInfo = null
  this.idAttributes = [ 'Id', 'ID' ];
  if (this.options.idAttribute) this.idAttributes.splice(0, 0, this.options.idAttribute);
}

SignedXml.CanonicalizationAlgorithms = {
  'http://www.w3.org/2001/10/xml-exc-c14n#': ExclusiveCanonicalization,
  'http://www.w3.org/2000/09/xmldsig#enveloped-signature': EnvelopedSignature
}

SignedXml.HashAlgorithms = {
  'http://www.w3.org/2000/09/xmldsig#sha1': SHA1,
  'http://www.w3.org/2001/04/xmlenc#sha256': SHA256
}

SignedXml.SignatureAlgorithms = {
  'http://www.w3.org/2000/09/xmldsig#rsa-sha1': RSASHA1,
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': RSASHA256
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

  if (!this.validateSignatureValue(doc)) {
    return false;
  }

  return true
}

SignedXml.prototype.validateSignatureValue = function(doc) {
  var signedInfo = utils.findChilds(this.signatureXmlDoc.documentElement, "SignedInfo") 
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
    var ref = this.references[r]    
    
    var uri = ref.uri[0]=="#" ? ref.uri.substring(1) : ref.uri
    var elem = [];
    for (var index in this.idAttributes) {
      elem = select(doc, "//*[@*[local-name(.)='" + this.idAttributes[index] + "']='" + uri + "']")
      if (elem.length > 0) break;
    }

    if (elem.length==0) {
      this.validationErrors.push("invalid signature: the signature refernces an element with uri "+
                        ref.uri + " but could not find such element in the xml")
      return false
    }
    
    var canonXml = this.getCanonXml(ref.transforms, elem[0])
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

SignedXml.prototype.loadSignature = function(signatureXml) {
  this.signatureXml = signatureXml

  var doc = new Dom().parseFromString(signatureXml)
  this.signatureXmlDoc = doc
  
  var nodes = select(doc, "//*[local-name(.)='CanonicalizationMethod']/@Algorithm")
  if (nodes.length==0) throw new Error("could not find CanonicalizationMethod/@Algorithm element")
  this.canonicalizationAlgorithm = nodes[0].value
  
  this.signatureAlgorithm = 
    utils.findFirst(doc, "//*[local-name(.)='SignatureMethod']/@Algorithm").value

  this.references = []
  var references = select(doc, "//*[local-name(.)='SignedInfo']/*[local-name(.)='Reference' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")
  if (references.length == 0) throw new Error("could not find any Reference elements")

  for (var i in references) {
    this.loadReference(references[i])    
  }

  this.signatureValue = 
    utils.findFirst(doc, "//*[local-name(.)='SignatureValue']/text()").data

  this.keyInfo = select(doc, "//*[local-name(.)='KeyInfo']")  
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
  nodes = utils.findChilds(ref, "Transforms")
  if (nodes.length!=0) {
    var transformsNode = nodes[0]
    var transformsAll = utils.findChilds(transformsNode, "Transform")  
    for (var t in transformsAll) {
      var trans = transformsAll[t]
      transforms.push(utils.findAttr(trans, "Algorithm").value)
    }
  }
  this.addReference(null, transforms, digestAlgo, utils.findAttr(ref, "URI").value, digestValue)
}

SignedXml.prototype.addReference = function(xpath, transforms, digestAlgorithm, uri, digestValue) {    
  this.references.push({
    "xpath": xpath, 
    "transforms": transforms ? transforms : ["http://www.w3.org/2001/10/xml-exc-c14n#"] ,    
    "digestAlgorithm": digestAlgorithm ? digestAlgorithm : "http://www.w3.org/2000/09/xmldsig#sha1",
    "uri": uri,
    "digestValue": digestValue
  });
}

/**
 * Compute the signature of the given xml (usign the already defined settings)
 *
 */
SignedXml.prototype.computeSignature = function(xml, xpathToNodeBeforeSignature) {  
  var doc = new Dom().parseFromString(xml)
  this.signatureXml = "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"                      
  
  var signedInfo = this.createSignedInfo(doc);
  this.signatureXml += signedInfo;
  this.signatureXml += this.createSignature(signedInfo);
  this.signatureXml += this.getKeyInfo()  
  this.signatureXml += "</Signature>"

  this.originalXmlWithIds = doc.toString()

  var signatureDoc = new Dom().parseFromString(this.signatureXml)
  if (xpathToNodeBeforeSignature) {
    var nodes = select(doc, xpathToNodeBeforeSignature);
    if (!nodes && nodes.length === 0) {
      doc.documentElement.appendChild(signatureDoc.documentElement);
    } else {
      var referenceNode = nodes[0];
      // insert before referenceNode.nextSibling
      doc.documentElement.insertBefore(signatureDoc.documentElement, referenceNode.nextSibling ? referenceNode.nextSibling : referenceNode);
    }
  } else {
    doc.documentElement.appendChild(signatureDoc.documentElement)
  }
  
  this.signedXml = doc.toString()
}

SignedXml.prototype.getKeyInfo = function() {
  var res = ""
  if (this.keyInfoProvider) {
    res += "<KeyInfo>"
    res += this.keyInfoProvider.getKeyInfo(this.signingKey)
    res += "</KeyInfo>"
  }
  return res
}

/**
 * Generate the Reference nodes (as part of the signature process)
 *
 */
SignedXml.prototype.createReferences = function(doc) {

  var res = ""
  for (var n in this.references) {
    var ref = this.references[n]
      , nodes = select(doc, ref.xpath)

    if (nodes.length==0) {
      throw new Error('the following xpath cannot be signed because it was not found: ' + ref.xpath)
    }

    for (var h in nodes) {      
      var node = nodes[h]
      var id = this.ensureHasId(node); 
      ref.uri = id
      res += "<Reference URI=\"#" + id + "\">" + 
                           "<Transforms>"      
      
      for (var t in ref.transforms) {
        var trans = ref.transforms[t]
        var transform = this.findCanonicalizationAlgorithm(trans)
        res += "<Transform Algorithm=\"" + transform.getAlgorithmName() + "\" />"
      }
      
      var canonXml = this.getCanonXml(ref.transforms, node)

      var digestAlgorithm = this.findHashAlgorithm(ref.digestAlgorithm)
      res += "</Transforms>"+
             "<DigestMethod Algorithm=\"" + digestAlgorithm.getAlgorithmName() + "\" />"+
              "<DigestValue>" + digestAlgorithm.getHash(canonXml) + "</DigestValue>"+
              "</Reference>"
    }
  }

  return res
}

SignedXml.prototype.getCanonXml = function(transforms, node) {    
  var nodeToSign = node  
  var canonXml = node.toString()
  for (var t in transforms) {
    var transform = this.findCanonicalizationAlgorithm(transforms[t])
    canonXml = transform.process(nodeToSign)
    var canonDoc = new Dom().parseFromString(canonXml)        
    nodeToSign = canonDoc.documentElement
  }
  return canonXml
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
      attr = utils.findAttr(node, this.idAttributes[index], null);
      break;
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
SignedXml.prototype.createSignedInfo = function(doc) {
  var transform = this.findCanonicalizationAlgorithm(this.canonicalizationAlgorithm)
  var algo = this.findSignatureAlgorithm(this.signatureAlgorithm)

  var res = "<SignedInfo>"
  res += "<CanonicalizationMethod Algorithm=\"" + transform.getAlgorithmName() + "\" />" +
          "<SignatureMethod Algorithm=\"" + algo.getAlgorithmName() + "\" />"

  res += this.createReferences(doc)
  res += "</SignedInfo>"
  return res
}

/**
 * Create the Signature element
 *
 */
SignedXml.prototype.createSignature = function(signedInfo) {
  //the canonicalization requires to get a valid xml node. 
  //we need to wrap the info in a dummy signature since it contains the default namespace.
  var dummySignatureWrapper = "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" +
                        signedInfo +
                        "</Signature>"
  
  var xml = new Dom().parseFromString(dummySignatureWrapper)
  //get the signedInfo
  var node = xml.documentElement.firstChild;
  var canAlgorithm = new this.findCanonicalizationAlgorithm(this.canonicalizationAlgorithm)
  var canonizedSignedInfo = canAlgorithm.process(node)  
  var signatureAlgorithm = this.findSignatureAlgorithm(this.signatureAlgorithm)
  this.signatureValue = signatureAlgorithm.getSignature(canonizedSignedInfo, this.signingKey)
  return "<SignatureValue>" + this.signatureValue + "</SignatureValue>"
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
