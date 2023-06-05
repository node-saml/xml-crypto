package org.nodejs.xmlcrypto;

import java.io.File;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.commons.io.FileUtils;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class HMACTest {
    
    public static final String NamespaceSpecNS = "http://www.w3.org/2000/xmlns/";
    
    private static final Logger LOGGER = LoggerFactory
            .getLogger(HMACTest.class);
    
    @Test
    public void testCreateHMACSignature() throws Exception {
        // generate key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA1");
        SecretKey secretKey = keyGenerator.generateKey();

        // generate DOM document
        DocumentBuilderFactory documentBuilderFactory
                = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory
                .newDocumentBuilder();
        Document document = documentBuilder.newDocument();
        Element rootElement = document.createElementNS("urn:test",
                "test:Root");
        rootElement.setAttributeNS(NamespaceSpecNS,
                "xmlns:test", "urn:test");
        document.appendChild(rootElement);
        
        XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory
                .getInstance("DOM");

        // XML Signature references
        List<Reference> references = new LinkedList<>();
        List<Transform> transforms = new LinkedList<>();
        Transform envTransform = xmlSignatureFactory.newTransform(
                CanonicalizationMethod.ENVELOPED,
                (C14NMethodParameterSpec) null);
        transforms.add(envTransform);
        Transform exclTransform = xmlSignatureFactory.newTransform(
                CanonicalizationMethod.EXCLUSIVE,
                (C14NMethodParameterSpec) null);
        transforms.add(exclTransform);
        Reference reference = xmlSignatureFactory.newReference("",
                xmlSignatureFactory.newDigestMethod(DigestMethod.SHA256,
                        null), transforms, null, null);
        references.add(reference);

        // XML Signature SignedInfo
        SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(
                xmlSignatureFactory.newCanonicalizationMethod(
                        CanonicalizationMethod.EXCLUSIVE,
                        (C14NMethodParameterSpec) null),
                xmlSignatureFactory.newSignatureMethod(
                        SignatureMethod.HMAC_SHA1,
                        null), references);

        // XML Signature KeyInfo
        KeyInfoFactory keyInfoFactory
                = xmlSignatureFactory.getKeyInfoFactory();
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections
                .singletonList(keyInfoFactory.newKeyName("some-key-name")));
        
        Element parentElement = document.getDocumentElement();
        DOMSignContext domSignContext = new DOMSignContext(
                secretKey, parentElement);
        domSignContext.setDefaultNamespacePrefix("ds");
        XMLSignature xmlSignature = xmlSignatureFactory.newXMLSignature(
                signedInfo, keyInfo);
        xmlSignature.sign(domSignContext);
        
        File tmpFile = File.createTempFile("xml-signature-hmac-", ".xml");
        LOGGER.debug("XML signature file: {}", tmpFile.getAbsolutePath());
        toFile(document, tmpFile);
        
        File tmpKeyFile = File.createTempFile("hmac-", ".key");
        FileUtils.writeByteArrayToFile(tmpKeyFile, secretKey.getEncoded());
        LOGGER.debug("key file: {}", tmpKeyFile.getAbsolutePath());
        
    }
    
    private void toFile(Node node, File file) throws Exception {
        TransformerFactory transformerFactory = TransformerFactory
                .newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.transform(new DOMSource(node), new StreamResult(file));
    }
}
