/* jshint laxcomma: true */
var utils = require('./utils')
  , Dom = require('xmldom-fork-fixed').DOMParser;

exports.ExclusiveCanonicalization = ExclusiveCanonicalization;

function ExclusiveCanonicalization() {}

ExclusiveCanonicalization.prototype.attrCompare = function(a,b) {
  if (!a.prefix && b.prefix) return -1;
  if (!b.prefix && a.prefix) return 1;
  return a.name.localeCompare(b.name);
};

ExclusiveCanonicalization.prototype.nsCompare = function(a,b) {
  var attr1 = a.prefix+a.namespaceURI;
  var attr2 = b.prefix+b.namespaceURI;
  if (attr1 == attr2) return 0;
  return attr1.localeCompare(attr2);
};

ExclusiveCanonicalization.prototype.renderAttrs = function(node) {
  var a, i, attr
    , res = []
    , attrListToRender = [];

  if (node.attributes) {
    for (i = 0; i < node.attributes.length; ++i) {
      attr = node.attributes[i];
      //ignore namespace definition attributes
      if (attr.name.indexOf("xmlns") === 0) continue;
      attrListToRender.push(attr);
    }
  }

  attrListToRender.sort(this.attrCompare);

  for (a in attrListToRender) {
    attr = attrListToRender[a];
    res.push(" ", attr.name, '="', utils.normalizeXmlIncludingCR(attr.value), '"');
  }

  return res.join("");
};


/**
 * Create the string of all namespace declarations that should appear on this element
 *
 * @param {Node} node. The node we now render
 * @param {Array} prefixesInScope. The prefixes defined on this node
 *                parents which are a part of the output set
 * @param {String} defaultNs. The current default namespace
 * @return {String}
 * @api private
 */
ExclusiveCanonicalization.prototype.renderNs = function(node, prefixesInScope, defaultNs, inclusiveNamespacesPrefixList) {
  var a, i, p, attr
    , res = []
    , newDefaultNs = defaultNs
    , nsListToRender = []
    , currNs = node.namespaceURI || "";

  //handle the namespaceof the node itself
  if (node.prefix) {
    if (prefixesInScope.indexOf(node.prefix)==-1) {
      nsListToRender.push({"prefix": node.prefix, "namespaceURI": node.namespaceURI});
      prefixesInScope.push(node.prefix);
    }
  }
  else if (defaultNs!=currNs) {
      //new default ns
      newDefaultNs = node.namespaceURI;
      res.push(' xmlns="', newDefaultNs, '"');
  }

  //handle the attributes namespace
  if (node.attributes) {
    for (i = 0; i < node.attributes.length; ++i) {
      attr = node.attributes[i];

      //handle all prefixed attributes that are included in the prefix list and where
      //the prefix is not defined already
      if (attr.prefix && prefixesInScope.indexOf(attr.localName) === -1 && inclusiveNamespacesPrefixList.indexOf(attr.localName) >= 0) {
        nsListToRender.push({"prefix": attr.localName, "namespaceURI": attr.value});
        prefixesInScope.push(attr.localName);
      }

      //handle all prefixed attributes that are not xmlns definitions and where
      //the prefix is not defined already
      if (attr.prefix && prefixesInScope.indexOf(attr.prefix)==-1 && attr.prefix!="xmlns") {
        nsListToRender.push({"prefix": attr.prefix, "namespaceURI": attr.namespaceURI});
        prefixesInScope.push(attr.prefix);
      }
    }
  }

  nsListToRender.sort(this.nsCompare);

  //render namespaces
  for (a in nsListToRender) {
    p = nsListToRender[a];
    res.push(" xmlns:", p.prefix, '="', p.namespaceURI, '"');
  }

  return {"rendered": res.join(""), "newDefaultNs": newDefaultNs};
};

ExclusiveCanonicalization.prototype.processInner = function(node, prefixesInScope, defaultNs, inclusiveNamespacesPrefixList) {
  if (node.data) return utils.normalizeXmlIncludingCR(node.data);

  var i, pfxCopy
    , ns = this.renderNs(node, prefixesInScope, defaultNs, inclusiveNamespacesPrefixList)
    , res = ["<", node.tagName, ns.rendered, this.renderAttrs(node), ">"];

  for (i = 0; i < node.childNodes.length; ++i) {
    pfxCopy = prefixesInScope.slice(0);
    res.push(this.processInner(node.childNodes[i], pfxCopy, ns.newDefaultNs, inclusiveNamespacesPrefixList));
  }

  res.push("</", node.tagName, ">");
  return res.join("");
};

/**
 * Perform canonicalization of the given node
 *
 * @param {Node} node
 * @return {String}
 * @api public
 */
ExclusiveCanonicalization.prototype.process = function(node, options) {
  options = options || {};
  var inclusiveNamespacesPrefixList = options.inclusiveNamespacesPrefixList || [];
  if (!(inclusiveNamespacesPrefixList instanceof Array)) inclusiveNamespacesPrefixList = inclusiveNamespacesPrefixList.split(' ');

  var res = this.processInner(node, [], "", inclusiveNamespacesPrefixList);
  return res;
  //var doc = new Dom().parseFromString(res)
  //return doc.documentElement
};

ExclusiveCanonicalization.prototype.getAlgorithmName = function() {
  return "http://www.w3.org/2001/10/xml-exc-c14n#";
};
