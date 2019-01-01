var crypto = require('../index');
var xpath = require('xpath');
var xmldom = require('xmldom');
var fs = require('fs');

exports['test validating HMAC signature'] = function (test) {
    var xml = fs.readFileSync('./test/static/hmac_signature.xml', 'utf-8');
    var doc = new xmldom.DOMParser().parseFromString(xml);
    var signature = xpath.select("/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']", doc)[0];
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
    var signature = xpath.select("/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']", doc)[0];
    var sig = new crypto.SignedXml();
    sig.keyInfoProvider = new crypto.FileKeyInfo("./test/static/hmac-foobar.key");
    sig.loadSignature(signature);
    var result = sig.checkSignature(xml);
    test.equal(result, false);
    test.done();
};


exports['test create and validate HMAC signature'] = function (test) {
    var xml = "<library>" +
            "<book>" +
            "<name>Harry Potter</name>" +
            "</book>" +
            "</library>";
    var sig = new crypto.SignedXml();
    sig.signingKey = fs.readFileSync("./test/static/hmac.key");
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
    sig.addReference("//*[local-name(.)='book']");
    sig.computeSignature(xml);

    var doc = new xmldom.DOMParser().parseFromString(sig.getSignedXml());
    var signature = xpath.select("/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']", doc)[0];
    var verify = new crypto.SignedXml();
    verify.keyInfoProvider = new crypto.FileKeyInfo("./test/static/hmac.key");
    verify.loadSignature(signature);
    var result = verify.checkSignature(sig.getSignedXml());
    test.equal(result, true);

    test.done();
};