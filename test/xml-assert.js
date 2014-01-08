var select = require('xpath.js')
  , dom = require('xmldom-fork-fixed').DOMParser


function nodeExists(test, doc, xpath) {  
  if (!doc && !xpath) return
  var node = select(doc, xpath)
  test.ok(node.length==1, "xpath " + xpath + " not found")  
}

exports.nodeExists = nodeExists
