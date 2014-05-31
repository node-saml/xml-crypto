var ExclusiveCanonicalization = require("../lib/exclusive-canonicalization").ExclusiveCanonicalization
  , Dom = require('xmldom-fork-fixed').DOMParser
  , select = require('xpath.js')
  , SignedXml = require('../lib/signed-xml.js').SignedXml


var compare = function(test, xml, xpath, expected, inclusiveNamespacesPrefixList) {
    test.expect(1)
    var doc = new Dom().parseFromString(xml)
    var elem = select(doc, xpath)[0]
    var can = new ExclusiveCanonicalization()
    var result = can.process(elem, { inclusiveNamespacesPrefixList: inclusiveNamespacesPrefixList }).toString()
    
    test.equal(expected, result)
    test.done()
}

module.exports = {

  "Exclusive canonicalization works on xml with no namespaces": function (test) {
    compare(test, 
      "<root><child>123</child></root>",
      "//*",
      "<root><child>123</child></root>")
	},

  "Exclusive canonicalization works on inner xpath": function (test) {
    compare(test, 
      "<root><child>123</child></root>",
      "//*[local-name(.)='child']",
      "<child>123</child>")
  },

  "Exclusive canonicalization works on xml with prefixed namespaces defined in output nodes": function (test) {
    compare(test, 
      "<root><p:child xmlns:p=\"s\"><inner>123</inner></p:child></root>",
      "//*[local-name(.)='child']",
      "<p:child xmlns:p=\"s\"><inner>123</inner></p:child>")
  },  

  "element used prefixed ns which is also the default": function (test) {
    compare(test, 
      "<root><child xmlns=\"s\"><p:inner xmlns:p=\"s\">123</p:inner></child></root>",
      "//*[local-name(.)='child']",
      "<child xmlns=\"s\"><p:inner xmlns:p=\"s\">123</p:inner></child>")
  },


  "Exclusive canonicalization works on xml with prefixed namespaces defined in output nodes. ns definition is not duplicated on each usage": function (test) {
    compare(test, 
      "<root><p:child xmlns:p=\"ns\"><p:inner>123</p:inner></p:child></root>",
      "//*[local-name(.)='child']",
      "<p:child xmlns:p=\"ns\"><p:inner>123</p:inner></p:child>")
  },


  "Exclusive canonicalization works on xml with prefixed namespaces defined in output nodes but before used": function (test) {
    compare(test, 
      "<root><child xmlns:p=\"ns\"><p:inner>123</p:inner></child></root>",
      "//*[local-name(.)='child']",
      "<child><p:inner xmlns:p=\"ns\">123</p:inner></child>")
  },


  "Exclusive canonicalization works on xml with prefixed namespaces defined outside output nodes": function (test) {
    compare(test, 
      "<root xmlns:p=\"ns\"><p:child>123</p:child></root>", 
      "//*[local-name(.)='child']", 
      "<p:child xmlns:p=\"ns\">123</p:child>")
  },

  "Exclusive canonicalization works on xml with prefixed namespace defined in inclusive list": function (test) {
    compare(test, 
      "<root xmlns:p=\"ns\"><p:child xmlns:inclusive=\"ns2\"><inclusive:inner xmlns:inclusive=\"ns2\">123</inclusive:inner></p:child></root>", 
      "//*[local-name(.)='child']", 
      "<p:child xmlns:inclusive=\"ns2\" xmlns:p=\"ns\"><inclusive:inner>123</inclusive:inner></p:child>",
      "inclusive")
  },

  "Exclusive canonicalization works on xml with multiple prefixed namespaces defined in inclusive list": function (test) {
    compare(test, 
      "<root xmlns:p=\"ns\"><p:child xmlns:inclusive=\"ns2\" xmlns:inclusive2=\"ns3\"><inclusive:inner xmlns:inclusive=\"ns2\">123</inclusive:inner><inclusive2:inner xmlns:inclusive2=\"ns3\">456</inclusive2:inner></p:child></root>", 
      "//*[local-name(.)='child']", 
      "<p:child xmlns:inclusive2=\"ns3\" xmlns:inclusive=\"ns2\" xmlns:p=\"ns\"><inclusive:inner>123</inclusive:inner><inclusive2:inner>456</inclusive2:inner></p:child>",
      "inclusive inclusive2")
  },

  "Exclusive canonicalization works on xml with prefixed namespace defined in inclusive list defined outside output nodes": function (test) {
    compare(test, 
      "<root xmlns:p=\"ns\" xmlns:inclusive=\"ns2\"><p:child><inclusive:inner xmlns:inclusive=\"ns2\">123</inclusive:inner></p:child></root>", 
      "//*[local-name(.)='child']", 
      "<p:child xmlns:p=\"ns\"><inclusive:inner xmlns:inclusive=\"ns2\">123</inclusive:inner></p:child>",
      "inclusive")
  },


  "Exclusive canonicalization works on xml with prefixed namespace defined in inclusive list used on attribute": function (test) {
    compare(test, 
      "<root xmlns:p=\"ns\"><p:child xmlns:inclusive=\"ns2\"><p:inner foo=\"inclusive:bar\">123</p:inner></p:child></root>", 
      "//*[local-name(.)='child']", 
      "<p:child xmlns:inclusive=\"ns2\" xmlns:p=\"ns\"><p:inner foo=\"inclusive:bar\">123</p:inner></p:child>",
      "inclusive")
  },


  "Exclusive canonicalization works on xml with default namespace inside output nodes": function (test) {
    compare(test, 
      "<root><child><inner xmlns=\"ns\">123</inner></child></root>", 
      "//*[local-name(.)='child']", 
      "<child><inner xmlns=\"ns\">123</inner></child>")
  },


  "Exclusive canonicalization works on xml with multiple different default namespaces": function (test) {
    compare(test, 
      "<root xmlns=\"ns1\"><child xmlns=\"ns2\"><inner xmlns=\"ns3\">123</inner></child></root>", 
      "//*[local-name(.)='child']", 
      "<child xmlns=\"ns2\"><inner xmlns=\"ns3\">123</inner></child>")
  },

"Exclusive canonicalization works on xml with multiple similar default namespaces": function (test) {
    compare(test, 
      "<root xmlns=\"ns1\"><child xmlns=\"ns2\"><inner xmlns=\"ns2\">123</inner></child></root>", 
      "//*[local-name(.)='child']", 
      "<child xmlns=\"ns2\"><inner>123</inner></child>")
  },


  "Exclusive canonicalization works on xml with default namespace outside output nodes": function (test) {
    compare(test, 
      "<root xmlns=\"ns\"><child><inner>123</inner></child></root>", 
      "//*[local-name(.)='child']", 
      "<child xmlns=\"ns\"><inner>123</inner></child>")
  },

  "Exclusive canonicalization works when prefixed namespace is defined in output nodes not in the parent chain of who needs it": function (test) {
    compare(test, 
      "<root><child><p:inner1 xmlns:p=\"foo\" /><p:inner2 xmlns:p=\"foo\" /></child></root>",
      "//*[local-name(.)='child']", 
      "<child><p:inner1 xmlns:p=\"foo\"></p:inner1><p:inner2 xmlns:p=\"foo\"></p:inner2></child>")
  },

  "Exclusive canonicalization works on xml with unordered attributes": function (test) {
    compare(test, 
      "<root><child xmlns:z=\"ns2\" xmlns:p=\"ns1\" p:name=\"val1\" z:someAttr=\"zval\" Id=\"value\" z:testAttr=\"ztestAttr\" someAttr=\"someAttrVal\" p:address=\"val2\"><inner>123</inner></child></root>", 
      "//*[local-name(.)='child']", 
      "<child xmlns:p=\"ns1\" xmlns:z=\"ns2\" Id=\"value\" someAttr=\"someAttrVal\" p:address=\"val2\" p:name=\"val1\" z:someAttr=\"zval\" z:testAttr=\"ztestAttr\"><inner>123</inner></child>")
  },

  "Exclusive canonicalization sorts upper case attributes before lower case": function (test) {
    compare(test, 
      "<x id=\"\" Id=\"\"></x>", 
      "//*[local-name(.)='x']", 
      "<x Id=\"\" id=\"\"></x>")
  },


  "Exclusive canonicalization works on xml with attributes with different namespace than element": function (test) {
    compare(test, 
      "<root><child xmlns=\"bla\" xmlns:p=\"foo\" p:attr=\"val\"><inner>123</inner></child></root>", 
      "//*[local-name(.)='child']", 
      "<child xmlns=\"bla\" xmlns:p=\"foo\" p:attr=\"val\"><inner>123</inner></child>")
  },


  "Exclusive canonicalization works on xml with attribute and element values with special characters": function (test) {
    compare(test, 
      "<root><child><inner attr=\"&amp;11\">&amp;11</inner></child></root>", 
      "//*[local-name(.)='child']", 
      "<child><inner attr=\"&amp;11\">&amp;11</inner></child>")
  },


  "Exclusive canonicalization preserves white space in values": function (test) {
    compare(test, 
      "<root><child><inner>12\r3\t</inner></child></root>", 
      "//*[local-name(.)='child']", 
      "<child><inner>12&#xD;3\t</inner></child>")
  },
  

  "Exclusive canonicalization preserves white space bewteen elements": function (test) {
    compare(test, 
      "<root><child><inner>123</inner>\r</child></root>", 
      "//*[local-name(.)='child']", 
      "<child><inner>123</inner>&#xD;</child>")
  },  


  "Exclusive canonicalization turns empty element to start-end tag pairs": function (test) {
    compare(test, 
      "<root><child><inner /></child></root>", 
      "//*[local-name(.)='child']", 
      "<child><inner></inner></child>")
  }, 


"Exclusive canonicalization preserves empty start-end tag pairs": function (test) {
    compare(test, 
      "<root><child><inner></inner></child></root>", 
      "//*[local-name(.)='child']", 
      "<child><inner></inner></child>")
  }, 


  "Exclusive canonicalization with empty default namespace outside output nodes": function (test) {
    compare(test, 
      "<root xmlns=\"\"><child><inner>123</inner></child></root>", 
      "//*[local-name(.)='child']", 
      "<child><inner>123</inner></child>")
  }, 


  "Exclusive canonicalization with empty default namespace inside output nodes": function (test) {
    compare(test, 
      "<root xmlns=\"foo\"><child><inner xmlns=\"\">123</inner></child></root>", 
      "//*[local-name(.)='child']", 
      "<child xmlns=\"foo\"><inner xmlns=\"\">123</inner></child>")
  }, 
  

  "The XML declaration and document type declaration (DTD) are removed": function (test) {
    compare(test, 
      "<?xml version=\"1.0\" encoding=\"utf-8\"?><root><child><inner>123</inner></child></root>", 
      "//*[local-name(.)='child']", 
      "<child><inner>123</inner></child>")
  },   
 

  "Attribute value delimiters are set to quotation marks (double quotes)": function (test) {
    compare(test, 
      "<root><child xmlns='ns'><inner attr='value'>123</inner></child></root>", 
      "//*[local-name(.)='child']", 
      "<child xmlns=\"ns\"><inner attr=\"value\">123</inner></child>")
  },

 
  "CDATA sections are replaced with their character content": function (test) {
    compare(test, 
      "<root><child><inner><![CDATA[foo & bar in the <x>123</x>]]></inner></child></root>", 
      "//*[local-name(.)='child']", 
      "<child><inner>foo &amp; bar in the &lt;x&gt;123&lt;/x&gt;</inner></child>")
  }, 

   "SignedInfo canonization": function (test) {
    compare(test, 
      "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/03/addressing\" xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"><soap:Header><wsa:Action wsu:Id=\"Id-fbcf79b7-9c1b-4e51-b3da-7d6c237be1ec\">http://stockservice.contoso.com/wse/samples/2003/06/StockQuoteRequest</wsa:Action><wsa:MessageID wsu:Id=\"Id-02b76fe1-945c-4e26-a8a5-6650285bbd4c\">uuid:6250c037-bcde-40ab-82b3-3a08efc86cdc</wsa:MessageID><wsa:ReplyTo wsu:Id=\"Id-ccc937f4-8ec8-416a-b97b-0b612a69b040\"><wsa:Address>http://schemas.xmlsoap.org/ws/2004/03/addressing/role/anonymous</wsa:Address></wsa:ReplyTo><wsa:To wsu:Id=\"Id-fa48ae82-88bb-4bf1-9c0d-4eb1de66c4fc\">http://localhost:8889/</wsa:To><wsse:Security soap:mustUnderstand=\"1\"><wsu:Timestamp wsu:Id=\"Timestamp-4d2cce4a-39fb-4d7d-b0d5-17d583255ef5\"><wsu:Created>2008-09-01T17:44:21Z</wsu:Created><wsu:Expires>2008-09-01T17:49:21Z</wsu:Expires></wsu:Timestamp><wsse:BinarySecurityToken ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"SecurityToken-d68c34d4-be89-4a29-aecc-971bce003ed3\">MIIBxDCCAW6gAwIBAgIQxUSXFzWJYYtOZnmmuOMKkjANBgkqhkiG9w0BAQQFADAWMRQwEgYDVQQDEwtSb290IEFnZW5jeTAeFw0wMzA3MDgxODQ3NTlaFw0zOTEyMzEyMzU5NTlaMB8xHTAbBgNVBAMTFFdTRTJRdWlja1N0YXJ0Q2xpZW50MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+L6aB9x928noY4+0QBsXnxkQE4quJl7c3PUPdVu7k9A02hRG481XIfWhrDY5i7OEB7KGW7qFJotLLeMec/UkKUwCgv3VvJrs2nE9xO3SSWIdNzADukYh+Cxt+FUU6tUkDeqg7dqwivOXhuOTRyOI3HqbWTbumaLdc8jufz2LhaQIDAQABo0swSTBHBgNVHQEEQDA+gBAS5AktBh0dTwCNYSHcFmRjoRgwFjEUMBIGA1UEAxMLUm9vdCBBZ2VuY3mCEAY3bACqAGSKEc+41KpcNfQwDQYJKoZIhvcNAQEEBQADQQAfIbnMPVYkNNfX1tG1F+qfLhHwJdfDUZuPyRPucWF5qkh6sSdWVBY5sT/txBnVJGziyO8DPYdu2fPMER8ajJfl</wsse:BinarySecurityToken><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" /><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\" /><Reference URI=\"#Id-fbcf79b7-9c1b-4e51-b3da-7d6c237be1ec\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" /><DigestValue>+465BlJx5xOfHsIFezQt0MS1vZQ=</DigestValue></Reference><Reference URI=\"#Id-02b76fe1-945c-4e26-a8a5-6650285bbd4c\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" /><DigestValue>jEe8rnaaqBWZQe+xHBQXriVG99o=</DigestValue></Reference><Reference URI=\"#Id-ccc937f4-8ec8-416a-b97b-0b612a69b040\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" /><DigestValue>W45ginYdBVqOqEaqPI2piZMPReA=</DigestValue></Reference><Reference URI=\"#Id-fa48ae82-88bb-4bf1-9c0d-4eb1de66c4fc\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" /><DigestValue>m2VlWz/ZDTWL7FREHK+wpKhvjJM=</DigestValue></Reference><Reference URI=\"#Timestamp-4d2cce4a-39fb-4d7d-b0d5-17d583255ef5\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" /><DigestValue>Qws229qmAzSTZ4OKmAUWgl0PWWo=</DigestValue></Reference><Reference URI=\"#Id-0175a715-4db3-4886-8af1-991b1472e7f4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" /><DigestValue>iEazGnkPY5caCWVZOHyR87CZ1h0=</DigestValue></Reference></SignedInfo><SignatureValue>Fkm7AbwiJCiOzY8ldfuA9pTW1G+EtE+UX4Cv7SoMIqeUdfWRDVHZpJAQyf7aoQnlpJNV/3k9L1PT6rJbfV478CkULJENPLm1m0fmDeLzhIHDEANuzp/AirC60tMD5jCARb4B4Nr/6bTmoyDQsTY8VLRiiINng7Mpweg1FZvd8a0=</SignatureValue><KeyInfo><wsse:SecurityTokenReference><wsse:Reference URI=\"#SecurityToken-d68c34d4-be89-4a29-aecc-971bce003ed3\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" /></wsse:SecurityTokenReference></KeyInfo></Signature></wsse:Security></soap:Header><soap:Body wsu:Id=\"Id-0175a715-4db3-4886-8af1-991b1472e7f4\"><StockQuoteRequest xmlns=\"http://stockservice.contoso.com/wse/samples/2003/06\"><symbols><Symbol>FABRIKAM</Symbol></symbols></StockQuoteRequest></soap:Body></soap:Envelope>", 
      "//*[local-name(.)='SignedInfo']", 
      "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><ds:CanonicalizationMethod xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:CanonicalizationMethod><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod><Reference URI=\"#Id-fbcf79b7-9c1b-4e51-b3da-7d6c237be1ec\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></Transform></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod><DigestValue>+465BlJx5xOfHsIFezQt0MS1vZQ=</DigestValue></Reference><Reference URI=\"#Id-02b76fe1-945c-4e26-a8a5-6650285bbd4c\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></Transform></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod><DigestValue>jEe8rnaaqBWZQe+xHBQXriVG99o=</DigestValue></Reference><Reference URI=\"#Id-ccc937f4-8ec8-416a-b97b-0b612a69b040\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></Transform></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod><DigestValue>W45ginYdBVqOqEaqPI2piZMPReA=</DigestValue></Reference><Reference URI=\"#Id-fa48ae82-88bb-4bf1-9c0d-4eb1de66c4fc\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></Transform></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod><DigestValue>m2VlWz/ZDTWL7FREHK+wpKhvjJM=</DigestValue></Reference><Reference URI=\"#Timestamp-4d2cce4a-39fb-4d7d-b0d5-17d583255ef5\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></Transform></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod><DigestValue>Qws229qmAzSTZ4OKmAUWgl0PWWo=</DigestValue></Reference><Reference URI=\"#Id-0175a715-4db3-4886-8af1-991b1472e7f4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></Transform></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod><DigestValue>iEazGnkPY5caCWVZOHyR87CZ1h0=</DigestValue></Reference></SignedInfo>")
  }, 

  "Exclusive canonicalization works on complex xml": function (test) {
    compare(test, 
      "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r" +
      "<Envelope xmlns=\"http://schemas.xmlsoap.org/soap/envelope/\">\r" +
      "  <Body>\r" +
      "    <ACORD xmlns=\"http://www.ACORD.org/standards/PC_Surety/ACORD1.10.0/xml/\">\r" +
      "      <SignonRq>\r" +
      "        <SessKey />\r" +
      "        <ClientDt />\r" +
      "        <CustLangPref />\r" +
      "        <ClientApp>\r" +
      "          <Org p6:type=\"AssignedIdentifier\" id=\"wewe\" xmlns:p6=\"http://www.w3.org/2001/XMLSchema-instance\" />\r" +
      "          <Name />\r" +
      "          <Version />\r" +
      "        </ClientApp>\r" +
      "        <ProxyClient>\r" +
      "          <Org p6:type=\"AssignedIdentifier\" id=\"erer\" xmlns:p6=\"http://www.w3.org/2001/XMLSchema-instance\" />\r" +
      "          <Name>ererer</Name>\r" +
      "          <Version>dfdf</Version>\r" +
      "        </ProxyClient>\r" +
      "      </SignonRq>\r" +
      "      <InsuranceSvcRq>\r" +
      "        <RqUID />\r" +
      "        <SPName id=\"rter\" />\r" +
      "        <QuickHit xmlns=\"urn:com.thehartford.bi.acord-extensions\">\r" +
      "          <StateProvCd CodeListRef=\"dfdf\" xmlns=\"http://www.ACORD.org/standards/PC_Surety/ACORD1.10.0/xml/\" />\r" +
      "        </QuickHit>\r" +
      "        <WorkCompPolicyQuoteInqRq>\r" +
      "          <RqUID>erer</RqUID>\r" +
      "          <TransactionRequestDt id=\"erer\" />\r" +
      "          <CurCd />\r" +
      "          <BroadLOBCd id=\"erer\" />\r" +
      "          <InsuredOrPrincipal>\r" +
      "            <ItemIdInfo>\r" +
      "              <AgencyId id=\"3434\" />\r" +
      "              <OtherIdentifier>\r" +
      "                <CommercialName id=\"3434\" />\r" +
      "                <ContractTerm>\r" +
      "                  <EffectiveDt id=\"3434\" />\r" +
      "                  <StartTime id=\"3434\" />\r" +
      "                </ContractTerm>\r" +
      "              </OtherIdentifier>\r" +
      "            </ItemIdInfo>\r" +
      "          </InsuredOrPrincipal>\r" +
      "          <InsuredOrPrincipal>\r" +
      "          </InsuredOrPrincipal>\r" +
      "          <CommlPolicy>\r" +
      "            <PolicyNumber id=\"3434\" />\r" +
      "            <LOBCd />\r" +
      "          </CommlPolicy>\r" +
      "          <WorkCompLineBusiness>\r" +
      "            <LOBCd />\r" +
      "            <WorkCompRateState>\r" +
      "              <WorkCompLocInfo>\r" +
      "              </WorkCompLocInfo>\r" +
      "            </WorkCompRateState>\r" +
      "          </WorkCompLineBusiness>\r" +
      "          <RemarkText IdRef=\"\">\r" +
      "          </RemarkText>\r" +
      "          <RemarkText IdRef=\"2323\" id=\"3434\">\r" +
      "          </RemarkText>\r" +
      "        </WorkCompPolicyQuoteInqRq>\r" +
      "      </InsuranceSvcRq>\r" +
      "    </ACORD>\r" +
      "  </Body>\r" +
      "</Envelope>",
      "//*[local-name(.)='Body']", 
      "<Body xmlns=\"http://schemas.xmlsoap.org/soap/envelope/\">&#xD;    <ACORD xmlns=\"http://www.ACORD.org/standards/PC_Surety/ACORD1.10.0/xml/\">&#xD;      <SignonRq>&#xD;        <SessKey></SessKey>&#xD;        <ClientDt></ClientDt>&#xD;        <CustLangPref></CustLangPref>&#xD;        <ClientApp>&#xD;          <Org xmlns:p6=\"http://www.w3.org/2001/XMLSchema-instance\" id=\"wewe\" p6:type=\"AssignedIdentifier\"></Org>&#xD;          <Name></Name>&#xD;          <Version></Version>&#xD;        </ClientApp>&#xD;        <ProxyClient>&#xD;          <Org xmlns:p6=\"http://www.w3.org/2001/XMLSchema-instance\" id=\"erer\" p6:type=\"AssignedIdentifier\"></Org>&#xD;          <Name>ererer</Name>&#xD;          <Version>dfdf</Version>&#xD;        </ProxyClient>&#xD;      </SignonRq>&#xD;      <InsuranceSvcRq>&#xD;        <RqUID></RqUID>&#xD;        <SPName id=\"rter\"></SPName>&#xD;        <QuickHit xmlns=\"urn:com.thehartford.bi.acord-extensions\">&#xD;          <StateProvCd xmlns=\"http://www.ACORD.org/standards/PC_Surety/ACORD1.10.0/xml/\" CodeListRef=\"dfdf\"></StateProvCd>&#xD;        </QuickHit>&#xD;        <WorkCompPolicyQuoteInqRq>&#xD;          <RqUID>erer</RqUID>&#xD;          <TransactionRequestDt id=\"erer\"></TransactionRequestDt>&#xD;          <CurCd></CurCd>&#xD;          <BroadLOBCd id=\"erer\"></BroadLOBCd>&#xD;          <InsuredOrPrincipal>&#xD;            <ItemIdInfo>&#xD;              <AgencyId id=\"3434\"></AgencyId>&#xD;              <OtherIdentifier>&#xD;                <CommercialName id=\"3434\"></CommercialName>&#xD;                <ContractTerm>&#xD;                  <EffectiveDt id=\"3434\"></EffectiveDt>&#xD;                  <StartTime id=\"3434\"></StartTime>&#xD;                </ContractTerm>&#xD;              </OtherIdentifier>&#xD;            </ItemIdInfo>&#xD;          </InsuredOrPrincipal>&#xD;          <InsuredOrPrincipal>&#xD;          </InsuredOrPrincipal>&#xD;          <CommlPolicy>&#xD;            <PolicyNumber id=\"3434\"></PolicyNumber>&#xD;            <LOBCd></LOBCd>&#xD;          </CommlPolicy>&#xD;          <WorkCompLineBusiness>&#xD;            <LOBCd></LOBCd>&#xD;            <WorkCompRateState>&#xD;              <WorkCompLocInfo>&#xD;              </WorkCompLocInfo>&#xD;            </WorkCompRateState>&#xD;          </WorkCompLineBusiness>&#xD;          <RemarkText IdRef=\"\">&#xD;          </RemarkText>&#xD;          <RemarkText IdRef=\"2323\" id=\"3434\">&#xD;          </RemarkText>&#xD;        </WorkCompPolicyQuoteInqRq>&#xD;      </InsuranceSvcRq>&#xD;    </ACORD>&#xD;  </Body>")
  },

  "Multiple Canonicalization with namespace definition outside of signed element": function (test) {
      //var doc = new Dom().parseFromString("<x xmlns:p=\"myns\"><p:y><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"></ds:Signature></p:y></x>")
      var doc = new Dom().parseFromString("<x xmlns:p=\"myns\"><p:y></p:y></x>")
      var node = select(doc, "//*[local-name(.)='y']")[0]      
      var sig = new SignedXml()
      var res = sig.getCanonXml(["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"], node)
      test.equal("<p:y xmlns:p=\"myns\"></p:y>", res)
      test.done()
  }, 

  "Enveloped-signature canonicalization respects currentnode": function(test) {
    // older versions of enveloped-signature removed the first signature in the whole doc, but should
    //   be the signature inside the current node if we want to be able to verify multiple signatures
    //   in a document.
    var xml = '<x><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" /><y><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" /></y></x>';
    var doc = new Dom().parseFromString(xml);
    var node = select(doc, "//*[local-name(.)='y']")[0];
    var sig = new SignedXml();
    var transforms = ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"];
    var res = sig.getCanonXml(transforms, node);
    test.equal("<y/>", res );
    test.done();
  },
}