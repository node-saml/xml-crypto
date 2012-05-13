exports.ExclusiveCanonicalization = ExclusiveCanonicalization

function ExclusiveCanonicalization() {

}

function attrCompare (a,b) {
  if (!a.prefix) return -1
  if (!b.prefix) return 1
  return a.name.localeCompare(b.name)
}

function nsCompare (a,b) {  
  var attr1 = a.prefix+a.namespaceURI
  var attr2 = b.prefix+b.namespaceURI
  return attr1.localeCompare(attr2)
}

function renderAttrs(node) {
  var res = ""
  var attrListToRender = []  

  if (node.attributes) {
    for (i=0;i<node.attributes.length;i++) {  
      var attr = node.attributes[i]
      //ignore namespace definition attributes
      if (attr.name.indexOf("xmlns")==0) continue;
      attrListToRender.push(attr)
    }
  }
  
  attrListToRender.sort(attrCompare)

  for (var a in attrListToRender) {
    var attr = attrListToRender[a]
    res += " " + attr.name + "=\"" + normalizeXml(attr.value) + "\"";
  }

  return res;
}

function renderNs(node, prefixesInScope, defaultNs) {
  var res = ""
  var newDefaultNs = defaultNs
  var nsListToRender = []

  var currNs = node.namespaceURI || ""
  //handle the node namespace
  
  if (node.prefix) {
    if (prefixesInScope.indexOf(node.prefix)==-1) {          
      nsListToRender.push({"prefix": node.prefix, "namespaceURI": node.namespaceURI})
      prefixesInScope.push(node.prefix);        
    }
  }
  else if (defaultNs!=currNs) {        
      //new default ns
      newDefaultNs = node.namespaceURI       
      res += " xmlns=\"" + newDefaultNs + "\""
  }  
  
  //handle the attributes namespace
  if (node.attributes) {
    for (i=0;i<node.attributes.length;i++) {          
      var attr = node.attributes[i]
      //handle all prefixed attributes that are not xmlns definitions and where 
      //the prefix is not defined already
      if (attr.prefix && prefixesInScope.indexOf(attr.prefix)==-1 && attr.prefix!="xmlns") {        
        nsListToRender.push({"prefix": attr.prefix, "namespaceURI": attr.namespaceURI})
        prefixesInScope.push(attr.prefix);
      }    
    }
  }
  
  nsListToRender.sort(nsCompare)  

  for (var a in nsListToRender) {    
    var p = nsListToRender[a]
    res += " xmlns:" + p.prefix + "=\"" + p.namespaceURI + "\"";
  }

  return {"rendered": res, "newDefaultNs": newDefaultNs};
}

function processInner(node, prefixesInScope, defaultNs) {

  if (node.data) return normalizeXml(node.data)
  
  var res = "<"
  res += node.tagName  
  var temp = renderNs(node, prefixesInScope, defaultNs)
  res += temp.rendered
  res += renderAttrs(node)    
  res+=">";

  for (var i=0;i<node.childNodes.length;i++) {    
    res += processInner(node.childNodes[i], prefixesInScope.slice(0), temp.newDefaultNs)
  }
  
  res+= "</" + node.tagName + ">"
  return res
}

ExclusiveCanonicalization.prototype.process = function(node) {    
  return processInner(node, [], "")
}

ExclusiveCanonicalization.prototype.getHash = function(xml) {
    var crypto = require('crypto')
      , shasum = crypto.createHash('sha1');
    shasum.update(xml);
    return shasum.digest('base64');
}

var xml_special_to_escaped_one_map = {
    '&': '&amp;',
    '"': '&quot;',
    '<': '&lt;',
    '>': '&gt;',
    '\r': '&#xD;'
};
 
var escaped_one_to_xml_special_map = {
    '&amp;': '&',
    '&quot;': '"',
    '&lt;': '<',
    '&gt;': '>',
    '&#xD;': '\r'
};
 
function normalizeXml(string) {
    return string.replace(/([\&"<>\r])/g, function(str, item) {
        return xml_special_to_escaped_one_map[item];
    });
};
 
function deNormalizeXml(string) {
    return string.replace(/(&quot;|&lt;|&gt;|&amp;|&#xD;)/g,
        function(str, item) {
            return escaped_one_to_xml_special_map[item];
    });
}
