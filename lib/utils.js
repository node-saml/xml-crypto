var select = require('xpath.js');

function findAttr(node, localName, namespace) {
  for (var i = 0; i<node.attributes.length; i++) {
  	var attr = node.attributes[i]  	

  	if (attrEqualsExplicitly(attr, localName, namespace) || attrEqualsImplicitly(attr, localName, namespace, node)) {  		  	
  		return attr
  	}
  }
  return null
}

function findFirst(doc, xpath) {  
  var nodes = select(doc, xpath)    
  if (nodes.length==0) throw "could not find xpath " + xpath
  return nodes[0]
}

function findChilds(node, localName, namespace) {
  node = node.documentElement || node;
  var res = []
  for (var i = 0; i<node.childNodes.length; i++) {
    var child = node.childNodes[i]       
    if (child.localName==localName && (child.namespaceURI==namespace || !namespace)) {
      res.push(child)
    }
  }
  return res
}

function attrEqualsExplicitly(attr, localName, namespace) {
	return attr.localName==localName && (attr.namespaceURI==namespace || !namespace)
}

function attrEqualsImplicitly(attr, localName, namespace, node) {
	return attr.localName==localName && ((!attr.namespaceURI && node.namespaceURI==namespace) || !namespace)
}

var xml_special_to_escaped_one_map = {
    '&': '&amp;',
    '"': '&quot;',
    '<': '&lt;',
    '>': '&gt;',
    '\r': '&#xD;'
}
 
var escaped_one_to_xml_special_map = {
    '&amp;': '&',
    '&quot;': '"',
    '&lt;': '<',
    '&gt;': '>',
    '&#xD;': '\r'
}
 
function normalizeXmlIncludingCR(string) {
    return string.replace(/([\&"<>\r])/g, function(str, item) {
        return xml_special_to_escaped_one_map[item];
    })
}
 
function deNormalizeXmlIncludingCR(string) {
    return string.replace(/(&quot;|&lt;|&gt;|&amp;|&#xD;)/g,
        function(str, item) {
            return escaped_one_to_xml_special_map[item];
    })
}

exports.findAttr = findAttr
exports.findChilds = findChilds
exports.normalizeXmlIncludingCR = normalizeXmlIncludingCR
exports.deNormalizeXmlIncludingCR = deNormalizeXmlIncludingCR
exports.findFirst = findFirst
