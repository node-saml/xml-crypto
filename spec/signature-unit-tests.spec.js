var select = require("xpath").select,
    dom = require("@xmldom/xmldom").DOMParser,
    SignedXml = require("../lib/signed-xml.js").SignedXml,
    FileKeyInfo = require("../lib/signed-xml.js").FileKeyInfo,
    fs = require("fs"),
    crypto = require("crypto");

describe("Signature unit tests", function () {

    it("signer adds increasing id attributes to elements", function () {
        verifyAddsId("wssecurity", "equal");
        verifyAddsId(null, "different");
    });

    it("signer adds references with namespaces", function () {
        verifyReferenceNS();
    });

    it("signer does not duplicate existing id attributes", function () {
        verifyDoesNotDuplicateIdAttributes(null, "");
        verifyDoesNotDuplicateIdAttributes("wssecurity", "wsu:");
    });

    it("signer adds custom attributes to the signature root node", function () {
        verifyAddsAttrs();

    });

    it("signer appends signature to the root node by default", function () {
        var xml = "<root><name>xml-crypto</name><repository>github</repository></root>";
        var sig = new SignedXml();

        sig.signingKey = fs.readFileSync("./spec/static/client.pem");
        sig.addReference("//*[local-name(.)='name']");
        sig.computeSignature(xml);

        var doc = new dom().parseFromString(sig.getSignedXml());

        expect(doc.documentElement.lastChild.localName)
            .withContext("the signature must be appended to the root node by default")
            .toBe("Signature");

    });

    it("signer appends signature to a reference node", function () {
        var xml = "<root><name>xml-crypto</name><repository>github</repository></root>";
        var sig = new SignedXml();

        sig.signingKey = fs.readFileSync("./spec/static/client.pem");
        sig.addReference("//*[local-name(.)='repository']");

        sig.computeSignature(xml, {
            location: {
                reference: "/root/name",
                action: "append",
            },
        });

        var doc = new dom().parseFromString(sig.getSignedXml());
        var referenceNode = select("/root/name", doc)[0];

        expect(referenceNode.lastChild.localName)
            .withContext("the signature should be appended to root/name")
            .toBe("Signature");

    });

    it("signer prepends signature to a reference node", function () {
        var xml = "<root><name>xml-crypto</name><repository>github</repository></root>";
        var sig = new SignedXml();

        sig.signingKey = fs.readFileSync("./spec/static/client.pem");
        sig.addReference("//*[local-name(.)='repository']");

        sig.computeSignature(xml, {
            location: {
                reference: "/root/name",
                action: "prepend",
            },
        });

        var doc = new dom().parseFromString(sig.getSignedXml());
        var referenceNode = select("/root/name", doc)[0];

        expect(referenceNode.firstChild.localName)
            .withContext("the signature should be prepended to root/name")
            .toBe("Signature");

    });

    it("signer inserts signature before a reference node", function () {
        var xml = "<root><name>xml-crypto</name><repository>github</repository></root>";
        var sig = new SignedXml();

        sig.signingKey = fs.readFileSync("./spec/static/client.pem");
        sig.addReference("//*[local-name(.)='repository']");

        sig.computeSignature(xml, {
            location: {
                reference: "/root/name",
                action: "before",
            },
        });

        var doc = new dom().parseFromString(sig.getSignedXml());
        var referenceNode = select("/root/name", doc)[0];

        expect(referenceNode.previousSibling.localName)
            .withContext("the signature should be inserted before to root/name")
            .toBe("Signature");

    });

    it("signer inserts signature after a reference node", function () {
        var xml = "<root><name>xml-crypto</name><repository>github</repository></root>";
        var sig = new SignedXml();

        sig.signingKey = fs.readFileSync("./spec/static/client.pem");
        sig.addReference("//*[local-name(.)='repository']");

        sig.computeSignature(xml, {
            location: {
                reference: "/root/name",
                action: "after",
            },
        });

        var doc = new dom().parseFromString(sig.getSignedXml());
        var referenceNode = select("/root/name", doc)[0];

        expect(referenceNode.nextSibling.localName)
            .withContext("the signature should be inserted after to root/name")
            .toBe("Signature");

    });

    it("signer creates signature with correct structure", function () {
        function DummyKeyInfo() {
            this.getKeyInfo = function () {
                return "dummy key info";
            };
        }

        function DummyDigest() {
            this.getHash = function () {
                return "dummy digest";
            };

            this.getAlgorithmName = function () {
                return "dummy digest algorithm";
            };
        }

        function DummySignatureAlgorithm() {
            this.getSignature = function () {
                return "dummy signature";
            };

            this.getAlgorithmName = function () {
                return "dummy algorithm";
            };
        }

        function DummyTransformation() {
            this.process = function () {
                return "< x/>";
            };

            this.getAlgorithmName = function () {
                return "dummy transformation";
            };
        }

        function DummyCanonicalization() {
            this.process = function () {
                return "< x/>";
            };

            this.getAlgorithmName = function () {
                return "dummy canonicalization";
            };
        }

        var xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';
        var sig = new SignedXml();

        SignedXml.CanonicalizationAlgorithms["http://DummyTransformation"] = DummyTransformation;
        SignedXml.CanonicalizationAlgorithms["http://DummyCanonicalization"] = DummyCanonicalization;
        SignedXml.HashAlgorithms["http://dummyDigest"] = DummyDigest;
        SignedXml.SignatureAlgorithms["http://dummySignatureAlgorithm"] = DummySignatureAlgorithm;

        sig.signatureAlgorithm = "http://dummySignatureAlgorithm";
        sig.keyInfoProvider = new DummyKeyInfo();
        sig.canonicalizationAlgorithm = "http://DummyCanonicalization";

        sig.addReference(
            "//*[local-name(.)='x']",
            ["http://DummyTransformation"],
            "http://dummyDigest"
        );
        sig.addReference(
            "//*[local-name(.)='y']",
            ["http://DummyTransformation"],
            "http://dummyDigest"
        );
        sig.addReference(
            "//*[local-name(.)='w']",
            ["http://DummyTransformation"],
            "http://dummyDigest"
        );

        sig.computeSignature(xml);
        var signature = sig.getSignatureXml();
        var expected =
            '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' +
            "<SignedInfo>" +
            '<CanonicalizationMethod Algorithm="dummy canonicalization"/>' +
            '<SignatureMethod Algorithm="dummy algorithm"/>' +
            '<Reference URI="#_0">' +
            "<Transforms>" +
            '<Transform Algorithm="dummy transformation"/>' +
            "</Transforms>" +
            '<DigestMethod Algorithm="dummy digest algorithm"/>' +
            "<DigestValue>dummy digest</DigestValue>" +
            "</Reference>" +
            '<Reference URI="#_1">' +
            "<Transforms>" +
            '<Transform Algorithm="dummy transformation"/>' +
            "</Transforms>" +
            '<DigestMethod Algorithm="dummy digest algorithm"/>' +
            "<DigestValue>dummy digest</DigestValue>" +
            "</Reference>" +
            '<Reference URI="#_2">' +
            "<Transforms>" +
            '<Transform Algorithm="dummy transformation"/>' +
            "</Transforms>" +
            '<DigestMethod Algorithm="dummy digest algorithm"/>' +
            "<DigestValue>dummy digest</DigestValue>" +
            "</Reference>" +
            "</SignedInfo>" +
            "<SignatureValue>dummy signature</SignatureValue>" +
            "<KeyInfo>" +
            "dummy key info" +
            "</KeyInfo>" +
            "</Signature>";

        expect(expected).withContext("wrong signature format").toEqual(signature);

        var signedXml = sig.getSignedXml();
        var expectedSignedXml =
            '<root><x xmlns="ns" Id="_0"/><y attr="value" Id="_1"/><z><w Id="_2"/></z>' +
            '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' +
            "<SignedInfo>" +
            '<CanonicalizationMethod Algorithm="dummy canonicalization"/>' +
            '<SignatureMethod Algorithm="dummy algorithm"/>' +
            '<Reference URI="#_0">' +
            "<Transforms>" +
            '<Transform Algorithm="dummy transformation"/>' +
            "</Transforms>" +
            '<DigestMethod Algorithm="dummy digest algorithm"/>' +
            "<DigestValue>dummy digest</DigestValue>" +
            "</Reference>" +
            '<Reference URI="#_1">' +
            "<Transforms>" +
            '<Transform Algorithm="dummy transformation"/>' +
            "</Transforms>" +
            '<DigestMethod Algorithm="dummy digest algorithm"/>' +
            "<DigestValue>dummy digest</DigestValue>" +
            "</Reference>" +
            '<Reference URI="#_2">' +
            "<Transforms>" +
            '<Transform Algorithm="dummy transformation"/>' +
            "</Transforms>" +
            '<DigestMethod Algorithm="dummy digest algorithm"/>' +
            "<DigestValue>dummy digest</DigestValue>" +
            "</Reference>" +
            "</SignedInfo>" +
            "<SignatureValue>dummy signature</SignatureValue>" +
            "<KeyInfo>" +
            "dummy key info" +
            "</KeyInfo>" +
            "</Signature>" +
            "</root>";

        expect(expectedSignedXml).withContext("wrong signedXml format").toEqual(signedXml);

        var originalXmlWithIds = sig.getOriginalXmlWithIds();
        var expectedOriginalXmlWithIds =
            '<root><x xmlns="ns" Id="_0"/><y attr="value" Id="_1"/><z><w Id="_2"/></z></root>';
        expect(expectedOriginalXmlWithIds).withContext("wrong OriginalXmlWithIds").toEqual(originalXmlWithIds);


    });

    it("signer creates signature with correct structure (with prefix)", function () {
        var prefix = "ds";

        function DummyKeyInfo() {
            this.getKeyInfo = function () {
                return "<ds:dummy>dummy key info</ds:dummy>";
            };
        }

        function DummyDigest() {
            this.getHash = function () {
                return "dummy digest";
            };

            this.getAlgorithmName = function () {
                return "dummy digest algorithm";
            };
        }

        function DummySignatureAlgorithm() {
            this.getSignature = function () {
                return "dummy signature";
            };

            this.getAlgorithmName = function () {
                return "dummy algorithm";
            };
        }

        function DummyTransformation() {
            this.process = function () {
                return "< x/>";
            };

            this.getAlgorithmName = function () {
                return "dummy transformation";
            };
        }

        function DummyCanonicalization() {
            this.process = function () {
                return "< x/>";
            };

            this.getAlgorithmName = function () {
                return "dummy canonicalization";
            };
        }

        var xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';
        var sig = new SignedXml();

        SignedXml.CanonicalizationAlgorithms["http://DummyTransformation"] = DummyTransformation;
        SignedXml.CanonicalizationAlgorithms["http://DummyCanonicalization"] = DummyCanonicalization;
        SignedXml.HashAlgorithms["http://dummyDigest"] = DummyDigest;
        SignedXml.SignatureAlgorithms["http://dummySignatureAlgorithm"] = DummySignatureAlgorithm;

        sig.signatureAlgorithm = "http://dummySignatureAlgorithm";
        sig.keyInfoProvider = new DummyKeyInfo();
        sig.canonicalizationAlgorithm = "http://DummyCanonicalization";

        sig.addReference(
            "//*[local-name(.)='x']",
            ["http://DummyTransformation"],
            "http://dummyDigest"
        );
        sig.addReference(
            "//*[local-name(.)='y']",
            ["http://DummyTransformation"],
            "http://dummyDigest"
        );
        sig.addReference(
            "//*[local-name(.)='w']",
            ["http://DummyTransformation"],
            "http://dummyDigest"
        );

        sig.computeSignature(xml, {prefix: prefix});
        var signature = sig.getSignatureXml();

        var expected =
            '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
            "<ds:SignedInfo>" +
            '<ds:CanonicalizationMethod Algorithm="dummy canonicalization"/>' +
            '<ds:SignatureMethod Algorithm="dummy algorithm"/>' +
            '<ds:Reference URI="#_0">' +
            "<ds:Transforms>" +
            '<ds:Transform Algorithm="dummy transformation"/>' +
            "</ds:Transforms>" +
            '<ds:DigestMethod Algorithm="dummy digest algorithm"/>' +
            "<ds:DigestValue>dummy digest</ds:DigestValue>" +
            "</ds:Reference>" +
            '<ds:Reference URI="#_1">' +
            "<ds:Transforms>" +
            '<ds:Transform Algorithm="dummy transformation"/>' +
            "</ds:Transforms>" +
            '<ds:DigestMethod Algorithm="dummy digest algorithm"/>' +
            "<ds:DigestValue>dummy digest</ds:DigestValue>" +
            "</ds:Reference>" +
            '<ds:Reference URI="#_2">' +
            "<ds:Transforms>" +
            '<ds:Transform Algorithm="dummy transformation"/>' +
            "</ds:Transforms>" +
            '<ds:DigestMethod Algorithm="dummy digest algorithm"/>' +
            "<ds:DigestValue>dummy digest</ds:DigestValue>" +
            "</ds:Reference>" +
            "</ds:SignedInfo>" +
            "<ds:SignatureValue>dummy signature</ds:SignatureValue>" +
            "<ds:KeyInfo>" +
            "<ds:dummy>dummy key info</ds:dummy>" +
            "</ds:KeyInfo>" +
            "</ds:Signature>";

        expect(expected).withContext("wrong signature format").toEqual(signature);

        var signedXml = sig.getSignedXml();
        var expectedSignedXml =
            '<root><x xmlns="ns" Id="_0"/><y attr="value" Id="_1"/><z><w Id="_2"/></z>' +
            '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
            "<ds:SignedInfo>" +
            '<ds:CanonicalizationMethod Algorithm="dummy canonicalization"/>' +
            '<ds:SignatureMethod Algorithm="dummy algorithm"/>' +
            '<ds:Reference URI="#_0">' +
            "<ds:Transforms>" +
            '<ds:Transform Algorithm="dummy transformation"/>' +
            "</ds:Transforms>" +
            '<ds:DigestMethod Algorithm="dummy digest algorithm"/>' +
            "<ds:DigestValue>dummy digest</ds:DigestValue>" +
            "</ds:Reference>" +
            '<ds:Reference URI="#_1">' +
            "<ds:Transforms>" +
            '<ds:Transform Algorithm="dummy transformation"/>' +
            "</ds:Transforms>" +
            '<ds:DigestMethod Algorithm="dummy digest algorithm"/>' +
            "<ds:DigestValue>dummy digest</ds:DigestValue>" +
            "</ds:Reference>" +
            '<ds:Reference URI="#_2">' +
            "<ds:Transforms>" +
            '<ds:Transform Algorithm="dummy transformation"/>' +
            "</ds:Transforms>" +
            '<ds:DigestMethod Algorithm="dummy digest algorithm"/>' +
            "<ds:DigestValue>dummy digest</ds:DigestValue>" +
            "</ds:Reference>" +
            "</ds:SignedInfo>" +
            "<ds:SignatureValue>dummy signature</ds:SignatureValue>" +
            "<ds:KeyInfo>" +
            "<ds:dummy>dummy key info</ds:dummy>" +
            "</ds:KeyInfo>" +
            "</ds:Signature>" +
            "</root>";

        expect(expectedSignedXml).withContext("wrong signedXml format").toEqual(signedXml);

        var originalXmlWithIds = sig.getOriginalXmlWithIds();
        var expectedOriginalXmlWithIds =
            '<root><x xmlns="ns" Id="_0"/><y attr="value" Id="_1"/><z><w Id="_2"/></z></root>';
        expect(expectedOriginalXmlWithIds).withContext("wrong OriginalXmlWithIds").toEqual(originalXmlWithIds);


    });

    it("signer creates correct signature values", function () {
        var xml =
            '<root><x xmlns="ns" Id="_0"></x><y attr="value" Id="_1"></y><z><w Id="_2"></w></z></root>';
        var sig = new SignedXml();
        sig.signingKey = fs.readFileSync("./spec/static/client.pem");
        sig.keyInfoProvider = null;

        sig.addReference("//*[local-name(.)='x']");
        sig.addReference("//*[local-name(.)='y']");
        sig.addReference("//*[local-name(.)='w']");

        sig.computeSignature(xml);
        var signedXml = sig.getSignedXml();
        var expected =
            '<root><x xmlns="ns" Id="_0"/><y attr="value" Id="_1"/><z><w Id="_2"/></z>' +
            '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' +
            "<SignedInfo>" +
            '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
            '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>' +
            '<Reference URI="#_0">' +
            "<Transforms>" +
            '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms>' +
            '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
            "<DigestValue>b5GCZ2xpP5T7tbLWBTkOl4CYupQ=</DigestValue>" +
            "</Reference>" +
            '<Reference URI="#_1">' +
            "<Transforms>" +
            '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
            "</Transforms>" +
            '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
            "<DigestValue>4Pq/sBri+AyOtxtSFsPSOyylyzk=</DigestValue>" +
            "</Reference>" +
            '<Reference URI="#_2">' +
            "<Transforms>" +
            '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
            "</Transforms>" +
            '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
            "<DigestValue>6I7SDu1iV2YOajTlf+iMLIBfLnE=</DigestValue>" +
            "</Reference>" +
            "</SignedInfo>" +
            "<SignatureValue>NejzGB9MDUddKCt3GL2vJhEd5q6NBuhLdQc3W4bJI5q34hk7Hk6zBRoW3OliX+/f7Hpi9y0INYoqMSUfrsAVm3IuPzUETKlI6xiNZo07ULRj1DwxRo6cU66ar1EKUQLRuCZas795FjB8jvUI2lyhcax/00uMJ+Cjf4bwAQ+9gOQ=</SignatureValue>" +
            "</Signature>" +
            "</root>";

        expect(expected).withContext("wrong signature format").toEqual(signedXml);


    });

    it("signer creates correct signature values using async callback", function () {
        function DummySignatureAlgorithm() {
            this.getSignature = function (signedInfo, signingKey, callback) {
                var signer = crypto.createSign("RSA-SHA1");
                signer.update(signedInfo);
                var res = signer.sign(signingKey, "base64");
                //Do some asynchronous things here
                callback(null, res);
            };
            this.getAlgorithmName = function () {
                return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
            };
        }

        var xml =
            '<root><x xmlns="ns" Id="_0"></x><y attr="value" Id="_1"></y><z><w Id="_2"></w></z></root>';
        SignedXml.SignatureAlgorithms["http://dummySignatureAlgorithmAsync"] = DummySignatureAlgorithm;
        var sig = new SignedXml();
        sig.signatureAlgorithm = "http://dummySignatureAlgorithmAsync";
        sig.signingKey = fs.readFileSync("./spec/static/client.pem");
        sig.keyInfoProvider = null;

        sig.addReference("//*[local-name(.)='x']");
        sig.addReference("//*[local-name(.)='y']");
        sig.addReference("//*[local-name(.)='w']");

        sig.computeSignature(xml, function () {
            var signedXml = sig.getSignedXml();
            var expected =
                '<root><x xmlns="ns" Id="_0"/><y attr="value" Id="_1"/><z><w Id="_2"/></z>' +
                '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' +
                "<SignedInfo>" +
                '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
                '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>' +
                '<Reference URI="#_0">' +
                "<Transforms>" +
                '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms>' +
                '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
                "<DigestValue>b5GCZ2xpP5T7tbLWBTkOl4CYupQ=</DigestValue>" +
                "</Reference>" +
                '<Reference URI="#_1">' +
                "<Transforms>" +
                '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
                "</Transforms>" +
                '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
                "<DigestValue>4Pq/sBri+AyOtxtSFsPSOyylyzk=</DigestValue>" +
                "</Reference>" +
                '<Reference URI="#_2">' +
                "<Transforms>" +
                '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
                "</Transforms>" +
                '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
                "<DigestValue>6I7SDu1iV2YOajTlf+iMLIBfLnE=</DigestValue>" +
                "</Reference>" +
                "</SignedInfo>" +
                "<SignatureValue>NejzGB9MDUddKCt3GL2vJhEd5q6NBuhLdQc3W4bJI5q34hk7Hk6zBRoW3OliX+/f7Hpi9y0INYoqMSUfrsAVm3IuPzUETKlI6xiNZo07ULRj1DwxRo6cU66ar1EKUQLRuCZas795FjB8jvUI2lyhcax/00uMJ+Cjf4bwAQ+9gOQ=</SignatureValue>" +
                "</Signature>" +
                "</root>";

            expect(expected).withContext("wrong signature format").toEqual(signedXml);

        });
    });

    it("correctly loads signature", function () {
        passLoadSignature("./spec/static/valid_signature.xml");
        passLoadSignature("./spec/static/valid_signature.xml", true);
        passLoadSignature("./spec/static/valid_signature_with_root_level_sig_namespace.xml");

    });

    it("verify valid signature", function () {
        passValidSignature("./spec/static/valid_signature.xml");
        passValidSignature("./spec/static/valid_signature_with_lowercase_id_attribute.xml");
        passValidSignature("./spec/static/valid_signature wsu.xml", "wssecurity");
        passValidSignature("./spec/static/valid_signature_with_reference_keyInfo.xml");
        passValidSignature("./spec/static/valid_signature_with_whitespace_in_digestvalue.xml");
        passValidSignature("./spec/static/valid_signature_utf8.xml");
        passValidSignature("./spec/static/valid_signature_with_unused_prefixes.xml");

    });

    it("fail invalid signature", function () {
        failInvalidSignature("./spec/static/invalid_signature - signature value.xml");
        failInvalidSignature("./spec/static/invalid_signature - hash.xml");
        failInvalidSignature("./spec/static/invalid_signature - non existing reference.xml");
        failInvalidSignature("./spec/static/invalid_signature - changed content.xml");
        failInvalidSignature(
            "./spec/static/invalid_signature - wsu - invalid signature value.xml",
            "wssecurity"
        );
        failInvalidSignature("./spec/static/invalid_signature - wsu - hash.xml", "wssecurity");
        failInvalidSignature(
            "./spec/static/invalid_signature - wsu - non existing reference.xml",
            "wssecurity"
        );
        failInvalidSignature(
            "./spec/static/invalid_signature - wsu - changed content.xml",
            "wssecurity"
        );
    });

    it("allow empty reference uri when signing", function () {
        var xml = "<root><x /></root>";
        var sig = new SignedXml();
        sig.signingKey = fs.readFileSync("./spec/static/client.pem");
        sig.keyInfoProvider = null;

        sig.addReference(
            "//*[local-name(.)='root']",
            ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"],
            "http://www.w3.org/2000/09/xmldsig#sha1",
            "",
            "",
            "",
            true
        );

        sig.computeSignature(xml);
        var signedXml = sig.getSignedXml();
        var doc = new dom().parseFromString(signedXml);
        var URI = select("//*[local-name(.)='Reference']/@URI", doc)[0];
        expect(URI.value)
            .withContext("uri should be empty but instead was " + URI.value)
            .toEqual("");
    });

    it("signer appends signature to a non-existing reference node", function () {
        var xml = "<root><name>xml-crypto</name><repository>github</repository></root>";
        var sig = new SignedXml();

        sig.signingKey = fs.readFileSync("./spec/static/client.pem");
        sig.addReference("//*[local-name(.)='repository']");

        try {
            sig.computeSignature(xml, {
                location: {
                    reference: "/root/foobar",
                    action: "append"
                }
            });
            fail("Expected an error to be thrown");
        } catch (err) {
            expect(err instanceof TypeError).toBeFalsy();
        }

    });

    it("signer adds existing prefixes", function () {
        function AssertionKeyInfo(assertionId) {
            this.getKeyInfo = function () {
                return (
                    '<wsse:SecurityTokenReference wsse11:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1" wsu:Id="0" ' +
                    'xmlns:wsse11="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"> ' +
                    '<wsse:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID">' +
                    assertionId +
                    "</wsse:KeyIdentifier>" +
                    "</wsse:SecurityTokenReference>"
                );
            };
        }

        var xml =
            '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"> ' +
            "<SOAP-ENV:Header> " +
            "<wsse:Security " +
            'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" ' +
            'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"> ' +
            "<Assertion></Assertion> " +
            "</wsse:Security> " +
            "</SOAP-ENV:Header> " +
            "</SOAP-ENV:Envelope>";

        var sig = new SignedXml();
        sig.keyInfoProvider = new AssertionKeyInfo("_81d5fba5c807be9e9cf60c58566349b1");
        sig.signingKey = fs.readFileSync("./spec/static/client.pem");
        sig.computeSignature(xml, {
            prefix: "ds",
            location: {
                reference: "//Assertion",
                action: "after",
            },
            existingPrefixes: {
                wsse: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
                wsu: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
            },
        });
        var result = sig.getSignedXml();
        expect((result.match(/xmlns:wsu=/g) || []).length).toEqual(1);
        expect((result.match(/xmlns:wsse=/g) || []).length).toEqual(1);
    });

    it("creates InclusiveNamespaces element when inclusiveNamespacesPrefixList is set on Reference",
        function () {
            var xml = "<root><x /></root>";
            var sig = new SignedXml();
            sig.signingKey = fs.readFileSync("./spec/static/client.pem");
            sig.keyInfoProvider = null;

            sig.addReference(
                "//*[local-name(.)='root']",
                ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"],
                "http://www.w3.org/2000/09/xmldsig#sha1",
                "",
                "",
                "prefix1 prefix2"
            );

            sig.computeSignature(xml);
            var signedXml = sig.getSignedXml();

            var doc = new dom().parseFromString(signedXml);
            var inclusiveNamespaces = select(
                "//*[local-name(.)='Reference']/*[local-name(.)='Transforms']/*[local-name(.)='Transform']/*[local-name(.)='InclusiveNamespaces']",
                doc.documentElement
            );
            expect(inclusiveNamespaces.length)
                .withContext("InclusiveNamespaces element should exist")
                .toEqual(1);

            var prefixListAttribute = inclusiveNamespaces[0].getAttribute("PrefixList");
            expect(prefixListAttribute)
                .withContext("InclusiveNamespaces element should have the correct PrefixList attribute value")
                .toEqual("prefix1 prefix2");
        });

    it("does not create InclusiveNamespaces element when inclusiveNamespacesPrefixList is not set on Reference",
        function () {
            var xml = "<root><x /></root>";
            var sig = new SignedXml();
            sig.signingKey = fs.readFileSync("./spec/static/client.pem");
            sig.keyInfoProvider = null;

            sig.addReference(
                "//*[local-name(.)='root']",
                ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"],
                "http://www.w3.org/2000/09/xmldsig#sha1",
                "",
                "",
                ""
            );

            sig.computeSignature(xml);
            var signedXml = sig.getSignedXml();

            var doc = new dom().parseFromString(signedXml);
            var inclusiveNamespaces = select(
                "//*[local-name(.)='Reference']/*[local-name(.)='Transforms']/*[local-name(.)='Transform']/*[local-name(.)='InclusiveNamespaces']",
                doc.documentElement
            );

            expect(inclusiveNamespaces.length)
                .withContext("InclusiveNamespaces element should not exist")
                .toEqual(0);

        });

    it("creates InclusiveNamespaces element inside CanonicalizationMethod when inclusiveNamespacesPrefixList is set on SignedXml options",
        function () {
            var xml = "<root><x /></root>";
            var sig = new SignedXml(null, {inclusiveNamespacesPrefixList: "prefix1 prefix2"});
            sig.signingKey = fs.readFileSync("./spec/static/client.pem");
            sig.keyInfoProvider = null;

            sig.addReference(
                "//*[local-name(.)='root']",
                ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"],
                "http://www.w3.org/2000/09/xmldsig#sha1"
            );

            sig.computeSignature(xml);
            var signedXml = sig.getSignedXml();

            var doc = new dom().parseFromString(signedXml);
            var inclusiveNamespaces = select(
                "//*[local-name(.)='CanonicalizationMethod']/*[local-name(.)='InclusiveNamespaces']",
                doc.documentElement
            );

            expect(inclusiveNamespaces.length).withContext("InclusiveNamespaces element should exist inside CanonicalizationMethod"
            ).toEqual(1);

            var prefixListAttribute = inclusiveNamespaces[0].getAttribute("PrefixList");
            expect(prefixListAttribute).withContext("InclusiveNamespaces element inside CanonicalizationMethod should have the correct PrefixList attribute value"
            ).toEqual("prefix1 prefix2");


        });

    it("does not create InclusiveNamespaces element inside CanonicalizationMethod when inclusiveNamespacesPrefixList is not set on SignedXml options",
        function () {
            var xml = "<root><x /></root>";
            var sig = new SignedXml(null); // Omit inclusiveNamespacesPrefixList property
            sig.signingKey = fs.readFileSync("./spec/static/client.pem");
            sig.keyInfoProvider = null;

            sig.addReference(
                "//*[local-name(.)='root']",
                ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"],
                "http://www.w3.org/2000/09/xmldsig#sha1"
            );

            sig.computeSignature(xml);
            var signedXml = sig.getSignedXml();

            var doc = new dom().parseFromString(signedXml);
            var inclusiveNamespaces = select(
                "//*[local-name(.)='CanonicalizationMethod']/*[local-name(.)='InclusiveNamespaces']",
                doc.documentElement
            );

            expect(inclusiveNamespaces.length).withContext("InclusiveNamespaces element should not exist inside CanonicalizationMethod"
            ).toEqual(0);


        });

    it("adds attributes to KeyInfo element when attrs are present in keyInfoProvider", function () {
        var xml = "<root><x /></root>";
        var sig = new SignedXml();
        sig.signingKey = fs.readFileSync("./spec/static/client.pem");
        sig.keyInfoProvider = {
            attrs: {
                CustomUri: "http://www.example.com/keyinfo",
                CustomAttribute: "custom-value",
            },
            getKeyInfo: function () {
                return "<dummy/>";
            },
        };

        sig.computeSignature(xml);
        var signedXml = sig.getSignedXml();

        var doc = new dom().parseFromString(signedXml);
        var keyInfoElement = select("//*[local-name(.)='KeyInfo']", doc.documentElement);
        expect(keyInfoElement.length).withContext("KeyInfo element should exist").toEqual(1);

        var algorithmAttribute = keyInfoElement[0].getAttribute("CustomUri");
        expect(algorithmAttribute)
            .withContext("KeyInfo element should have the correct CustomUri attribute value")
            .toEqual("http://www.example.com/keyinfo");

        var customAttribute = keyInfoElement[0].getAttribute("CustomAttribute");
        expect(customAttribute)
            .withContext("KeyInfo element should have the correct CustomAttribute attribute value")
            .toEqual("custom-value");

    });

});

function passValidSignature(file, mode) {
    var xml = fs.readFileSync(file).toString();
    var res = verifySignature(xml, mode);
    expect(res).withContext("expected signature to be valid, but it was reported invalid").toBe(true);
}

function passLoadSignature(file, toString) {
    var xml = fs.readFileSync(file).toString();
    var doc = new dom().parseFromString(xml);
    var node = select(
        "/*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
        doc
    )[0];
    var sig = new SignedXml();
    sig.loadSignature(toString ? node.toString() : node);

    expect(sig.canonicalizationAlgorithm)
        .withContext("wrong canonicalization method")
        .toEqual("http://www.w3.org/2001/10/xml-exc-c14n#");

    expect(sig.signatureAlgorithm)
        .withContext("wrong signature method")
        .toEqual("http://www.w3.org/2000/09/xmldsig#rsa-sha1");

    expect(sig.signatureValue)
        .withContext("wrong signature value")
        .toEqual("PI2xGt3XrVcxYZ34Kw7nFdq75c7Mmo7J0q7yeDhBprHuJal/KV9KyKG+Zy3bmQIxNwkPh0KMP5r1YMTKlyifwbWK0JitRCSa0Fa6z6+TgJi193yiR5S1MQ+esoQT0RzyIOBl9/GuJmXx/1rXnqrTxmL7UxtqKuM29/eHwF0QDUI=");

    var keyInfo = select(
        "//*[local-name(.)='KeyInfo']/*[local-name(.)='dummyKey']",
        sig.keyInfo[0]
    )[0];
    expect(keyInfo.firstChild.data)
        .withContext("keyInfo clause not correctly loaded")
        .toEqual("1234");

    expect(sig.references.length).toEqual(3);

    var digests = [
        "b5GCZ2xpP5T7tbLWBTkOl4CYupQ=",
        "K4dI497ZCxzweDIrbndUSmtoezY=",
        "sH1gxKve8wlU8LlFVa2l6w3HMJ0=",
    ];

    for (var i = 0; i < sig.references.length; i++) {
        var ref = sig.references[i];
        var expectedUri = "#_" + i;
        expect(ref.uri)
            .withContext("wrong uri for index " + i + ". expected: " + expectedUri + " actual: " + ref.uri)
            .toEqual(expectedUri);
        expect(ref.transforms.length).toEqual(1);
        expect(ref.transforms[0]).toEqual("http://www.w3.org/2001/10/xml-exc-c14n#");
        expect(ref.digestValue).toEqual(digests[i]);
        expect(ref.digestAlgorithm).toEqual("http://www.w3.org/2000/09/xmldsig#sha1");
    }
}

function failInvalidSignature(file, mode) {
    var xml = fs.readFileSync(file).toString();
    var res = verifySignature(xml, mode);
    expect(res).withContext("expected signature to be invalid, but it was reported valid").toBe(false);
}

function verifySignature(xml, mode) {
    var doc = new dom().parseFromString(xml);
    var node = select(
        "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
        doc
    )[0];

    var sig = new SignedXml(mode);
    sig.keyInfoProvider = new FileKeyInfo("./spec/static/client_public.pem");
    sig.loadSignature(node);
    var res = sig.checkSignature(xml);

    return res;
}

function verifyDoesNotDuplicateIdAttributes(mode, prefix) {
    var xml =
        "<x xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' " +
        prefix +
        "Id='_1'></x>";
    var sig = new SignedXml(mode);
    sig.signingKey = fs.readFileSync("./spec/static/client.pem");
    sig.addReference("//*[local-name(.)='x']");
    sig.computeSignature(xml);
    var signedXml = sig.getOriginalXmlWithIds();
    var doc = new dom().parseFromString(signedXml);
    var attrs = select("//@*", doc);
    expect(attrs.length).withContext("wrong number of attributes").toEqual(2);
}

function verifyAddsId(mode, nsMode) {
    var xml = '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';
    var sig = new SignedXml(mode);
    sig.signingKey = fs.readFileSync("./spec/static/client.pem");

    sig.addReference("//*[local-name(.)='x']");
    sig.addReference("//*[local-name(.)='y']");
    sig.addReference("//*[local-name(.)='w']");

    sig.computeSignature(xml);
    var signedXml = sig.getOriginalXmlWithIds();
    var doc = new dom().parseFromString(signedXml);

    var op = nsMode == "equal" ? "=" : "!=";

    var xpath =
        "//*[local-name(.)='{elem}' and '_{id}' = @*[local-name(.)='Id' and namespace-uri(.)" +
        op +
        "'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd']]";

    //verify each of the signed nodes now has an "Id" attribute with the right value
    nodeExists(doc, xpath.replace("{id}", "0").replace("{elem}", "x"));
    nodeExists(doc, xpath.replace("{id}", "1").replace("{elem}", "y"));
    nodeExists(doc, xpath.replace("{id}", "2").replace("{elem}", "w"));
}

function verifyAddsAttrs() {
    var xml = '<root xmlns="ns"><name>xml-crypto</name><repository>github</repository></root>';
    var sig = new SignedXml();
    var attrs = {
        Id: "signatureTest",
        data: "dataValue",
        xmlns: "http://custom-xmlns#",
    };

    sig.signingKey = fs.readFileSync("./spec/static/client.pem");

    sig.addReference("//*[local-name(.)='name']");

    sig.computeSignature(xml, {
        attrs: attrs,
    });

    var signedXml = sig.getSignatureXml();
    var doc = new dom().parseFromString(signedXml);
    var signatureNode = doc.documentElement;

    expect(attrs.Id)
        .withContext('Id attribute is not equal to the expected value: "' + attrs.Id + '"')
        .toBe(signatureNode.getAttribute("Id"));
    expect(attrs.data)
        .withContext('data attribute is not equal to the expected value: "' + attrs.data + '"')
        .toBe(signatureNode.getAttribute("data"));
    expect(attrs.xmlns)
        .withContext("xmlns attribute can not be overriden")
        .not.toBe(signatureNode.getAttribute("xmlns"));
    expect(signatureNode.getAttribute("xmlns"))
        .withContext('xmlns attribute is not equal to the expected value: "http://www.w3.org/2000/09/xmldsig#"')
        .toBe("http://www.w3.org/2000/09/xmldsig#");
}

function verifyReferenceNS() {
    var xml =
        '<root xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><name wsu:Id="_1">xml-crypto</name><repository wsu:Id="_2">github</repository></root>';
    var sig = new SignedXml("wssecurity");

    sig.signingKey = fs.readFileSync("./spec/static/client.pem");

    sig.addReference("//*[@wsu:Id]");

    sig.computeSignature(xml, {
        existingPrefixes: {
            wsu: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
        },
    });

    var signedXml = sig.getSignatureXml();
    var doc = new dom().parseFromString(signedXml);
    var references = select("//*[local-name(.)='Reference']", doc);
    expect(references.length).toEqual(2);
}

function nodeExists(doc, xpath) {
    if (!doc && !xpath) return;
    var node = select(xpath, doc);
    expect(node.length).withContext("xpath " + xpath + " not found").toBe(1);
}