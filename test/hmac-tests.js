var crypto = require('../index');
var xmldom = require('xmldom');
var fs = require('fs');

exports['test validating HMAC signature'] = function (test) {
    var xml = fs.readFileSync('./test/static/hmac_signature.xml', 'utf-8');
    var doc = new xmldom.DOMParser().parseFromString(xml);
    var signature = crypto.xpath(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
    var sig = new crypto.SignedXml();
    sig.keyInfoProvider = new crypto.FileKeyInfo("./test/static/hmac.key");
    sig.loadSignature(signature);
    var result = sig.checkSignature(xml);
    test.equal(result, true);
    test.done();
};

exports['test HMAC signature with incorrect key'] = function (test) {
    var xml = fs.readFileSync('./test/static/hmac_signature.xml', 'utf-8');
    var doc = new xmldom.DOMParser().parseFromString(xml);
    var signature = crypto.xpath(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
    var sig = new crypto.SignedXml();
    sig.keyInfoProvider = new crypto.FileKeyInfo("./test/static/hmac-foobar.key");
    sig.loadSignature(signature);
    var result = sig.checkSignature(xml);
    test.equal(result, false);
    test.done();
};
