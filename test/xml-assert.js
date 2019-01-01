var select = require('xpath').select

function nodeExists(test, doc, xpath) {  
  if (!doc && !xpath) return
  var node = select(xpath, doc)
  test.ok(node.length==1, "xpath " + xpath + " not found")  
}

exports.nodeExists = nodeExists
