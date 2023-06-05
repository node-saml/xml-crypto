var crypto = require("../index");
var xpath = require("xpath");
var xmldom = require("@xmldom/xmldom");
var fs = require("fs");

describe("SAML response tests", function () {

    it("test validating SAML response", function () {
        var xml = fs.readFileSync("./spec/static/valid_saml.xml", "utf-8");
        var doc = new xmldom.DOMParser().parseFromString(xml);
        var signature = xpath.select(
            "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
            doc
        )[0];
        var sig = new crypto.SignedXml();
        sig.keyInfoProvider = new crypto.FileKeyInfo("./spec/static/feide_public.pem");
        sig.loadSignature(signature);
        var result = sig.checkSignature(xml);

        expect(result).toBe(true);
    });

    it("test validating wrapped assertion signature", function () {
        var xml = fs.readFileSync("./spec/static/valid_saml_signature_wrapping.xml", "utf-8");
        var doc = new xmldom.DOMParser().parseFromString(xml);
        var assertion = xpath.select("//*[local-name(.)='Assertion']", doc)[0];
        var signature = xpath.select(
            "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
            assertion
        )[0];
        var sig = new crypto.SignedXml();
        sig.keyInfoProvider = new crypto.FileKeyInfo("./spec/static/feide_public.pem");
        sig.loadSignature(signature);
        expect(function () {sig.checkSignature(xml)})
            .withContext("Should not validate a document which contains multiple elements with the " +
            "same value for the ID / Id / Id attributes, in order to prevent " +
            "signature wrapping attack.")
            .toThrow();
    });

    it("test validating SAML response where a namespace is defined outside the signed element",
        function () {
            var xml = fs.readFileSync("./spec/static/saml_external_ns.xml", "utf-8");
            var doc = new xmldom.DOMParser().parseFromString(xml);
            var signature = xpath.select(
                "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
                doc
            )[0];
            var sig = new crypto.SignedXml();
            sig.keyInfoProvider = new crypto.FileKeyInfo("./spec/static/saml_external_ns.pem");
            sig.loadSignature(signature);
            var result = sig.checkSignature(xml);
            expect(result).toBe(true);
        });

    it("test reference id does not contain quotes", function () {
        var xml = fs.readFileSync("./spec/static/id_with_quotes.xml", "utf-8");
        var doc = new xmldom.DOMParser().parseFromString(xml);
        var assertion = xpath.select("//*[local-name(.)='Assertion']", doc)[0];
        var signature = xpath.select(
            "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
            assertion
        )[0];
        var sig = new crypto.SignedXml();
        sig.keyInfoProvider = new crypto.FileKeyInfo("./spec/static/feide_public.pem");
        sig.loadSignature(signature);
        expect(function () {sig.checkSignature(xml)})
            .withContext("id should not contain quotes")
            .toThrow();
    });

    it("test validating SAML response WithComments", function () {
        var xml = fs.readFileSync("./spec/static/valid_saml_withcomments.xml", "utf-8");
        var doc = new xmldom.DOMParser().parseFromString(xml);
        var signature = xpath.select(
            "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
            doc
        )[0];
        var sig = new crypto.SignedXml();
        sig.keyInfoProvider = new crypto.FileKeyInfo("./spec/static/feide_public.pem");
        sig.loadSignature(signature);
        var result = sig.checkSignature(xml);
        // This doesn't matter, just want to make sure that we don't fail due to unknown algorithm
        expect(result).toBe(false);
    });

});
