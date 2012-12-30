var select = require('../lib/xpath.js').SelectNodes
  , dom = require('xmldom').DOMParser
  , SignedXml = require('../lib/signed-xml.js').SignedXml
  , fs = require('fs')
  
module.exports = {    

  "verify signature": function (test) {
  	var xml = "<root><x xmlns=\"ns\"></x><y z_attr=\"value\" a_attr1=\"foo\"></y><z><ns:w ns:attr=\"value\" xmlns:ns=\"myns\"></ns:w></z></root>"
    verifySignature(test, xml, [
      "//*[local-name(.)='x']", 
      "//*[local-name(.)='y']", 
      "//*[local-name(.)='w']"])
  },

  "verify signature of complex element": function (test) {
    var xml = "<library>" +
                "<book>" +
                  "<name>Harry Potter</name>" +
                  "<author id=\"123456789\">" +
                    "<firstName>Joanne K</firstName>" +
                    "<lastName>Rowling</lastName>" +
                  "</author>" +
                "</book>" +
              "</library>"

    verifySignature(test, xml, ["//*[local-name(.)='book']"])
  }

}

function verifySignature(test, xml, xpath) {  
  if (process.platform !== 'win32') {
    test.done();
    return;
  }
  var sig = new SignedXml()
  sig.signingKey = fs.readFileSync("./test/static/client.pem")
  sig.keyInfoCaluse = null
  
  xpath.map(function(n) { sig.addReference(n) })

  sig.computeSignature(xml)
  var signed = sig.getSignedXml()

  fs.writeFileSync("./test/validators/XmlCryptoUtilities/XmlCryptoUtilities/bin/Debug/signedExample.xml", signed)    
  
  var spawn = require('child_process').spawn
  var proc = spawn('./test/validators/XmlCryptoUtilities/XmlCryptoUtilities/bin/Debug/XmlCryptoUtilities.exe', ['verify'])

  proc.stdout.on('data', function (data) {
    console.log('stdout: ' + data);
  });

  proc.stderr.on('data', function (data) {
    console.log('stderr: ' + data);
  });

  proc.on('exit', function (code) {   
    test.equal(0, code, "signature validation failed")
    test.done()
  }); 

}
