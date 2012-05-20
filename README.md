## Xml-Crypto
A pure javascript xml digital signature library. Xml encryption is coming soon.

For more information visit my [blog](http://webservices20.blogspot.com/).

## Install
Install with [npm](http://github.com/isaacs/npm):

    npm install xml-crypto

A pre requisite it to have [openssl](http://www.openssl.org/) installed and its /bin to be on the system path (this is so that node's built-in crypto module would work - xml-crypto does not use openssl directly)
I used version 1.0.1c but it should probably work on older versions too.

## Signing Xml documents
	var SignedXml = require('xml-crypto').SignedXml
	  , FileKeyInfo = require('xml-crypto').FileKeyInfo  
	  , fs = require('fs')

	var xml = "<library>" +
	            "<book>" +
	              "<name>Harry Potter</name>" +
	            "</book>"
	          "</library>"

	var sig = new SignedXml()
	sig.addReference("//*[local-name(.)='book']")    
	sig.signingKey = fs.readFileSync("client.pem")
	sig.computeSignature(xml)
	fs.writeFileSync("signed.xml", sig.getSignedXml())

Notes:

sig.getSignedXml() returns the original xml document, with the signature pushed as the last child of the root node:

	<library>
		<book>
			...
		</book>
		<Signature>
			...
		</Signature>	
	</library>

This assumes you are not signing the root node but only sub node(s), otherwise it is not legal to put anything inside the root node (including the signature). If you do sign the root node, or have any other reason not to put the signature inside the signed document, you can alternatively call sig.getSignatureXml() to get just the signature element. You can then call sig.getOriginalXmlWithIds() to get the original xml, without the signature, but with the Id attrributes that the signature added on it so it can be validated.

## Verifying Xml documents

This sample uses [xmldom](https://github.com/jindw/xmldom) for xml dom manipulation. 
You can use whichever dom parser you want.

	var select = require('xml-crypto').SelectNodes
	  , dom = require('xmldom').DOMParser
	  , SignedXml = require('xml-crypto').SignedXml
	  , FileKeyInfo = require('xml-crypto').FileKeyInfo  
	  , fs = require('fs')

	var xml = fs.readFileSync("signed.xml").toString()
	var doc = new dom().parseFromString(xml)    

	var signature = select(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0]
	var sig = new SignedXml()
	sig.keyInfoProvider = new FileKeyInfo("client_public.pem")
	sig.loadSignature(signature.toString())
	var res = sig.checkSignature(xml)
	if (!res) console.log(sig.validationErrors)

Note: 

The xml-crypto api requires you to supply it separately the xml signature ("<Signature>...</Signature>") and the signed xml. The signed xml may contain the signature in it, but you are still required to supply the signature separately. As mentioned before, if the signature is inside the signed document it is not allowed to be under the scope of a signed element since it will make the signature invalid (unless special canonicalization is used).

## Supported Algorithms
The first release always uses the following algorithems:

* Exclusive Canonicalization http://www.w3.org/2001/10/xml-exc-c14n#
* SHA1 digests http://www.w3.org/2000/09/xmldsig#sha1
* RSA-SHA1 signature algorithm http://www.w3.org/2000/09/xmldsig#rsa-sha1

you are able to extend xml-crypto with further algorithms.

## Customizing Algorithms
The following sample shows how to sign a message using custom algorithms:

	var SignedXml = require('xml-crypto').SignedXml
	  , FileKeyInfo = require('xml-crypto').FileKeyInfo  
	  , fs = require('fs')

	/*A key info provider to extract and construct the key and the KeyInfo xml section*/
	function MyKeyInfo() {
	  this.getKeyInfo = function(key) {
	    return "this will appear under <KeyInfo></KeyInfo>"
	  }
	  this.getKey = function(keyInfo) {
	    //you can use the keyInfo parameter to extract the key in any way you want      
	    return fs.readFileSync("key.pem")
	  }
	}

	/*A custom hash algorithm*/
	function MyDigest() {


	  this.getHash = function(xml) {    
	    return "the base64 hash representation of the given xml string"
	  }

	  this.getAlgorithmName = function() {
	    return "http://myDigestAlgorithm"
	  }
	}

	/*A custom signing algorithm*/
	function MySignatureAlgorithm() {

	  /*sign the given SignedInfo using the key. return base64 signature value*/
	  this.getSignature = function(signedInfo, signingKey) {            
	    return "signature as base64..."
	  }

	  this.getAlgorithmName = function() {
	    return "http://mySigningAlgorithm"
	  }

	}

	/*Custom transformation (canonicalization) algorithm*/
	function MyTransformation() {
	  
	  /*given a node (from the xmldom module) return its canonical representation (as string)*/
	  this.process = function(node) {
	    return "< x/>"
	  }

	  this.getAlgorithmName = function() {
	    return "http://myTransformation"
	  }
	}

	/*Custom canonicalization algorithm. same as MyTransformation*/
	function MyCanonicalization() {

	  /*given a node (from the xmldom module) return its canonical representation (as string)*/
	  this.process = function(node) {
	    return "< x/>"
	  }

	   this.getAlgorithmName = function() {
	    return "http://myCanonicalization"
	  }
	}

	/*register all the custom algorithms*/

	SignedXml.CanonicalizationAlgorithms["http://MyTransformation"] = MyTransformation
	SignedXml.CanonicalizationAlgorithms["http://MyCanonicalization"] = MyCanonicalization
	SignedXml.HashAlgorithms["http://myDigestAlgorithm"] = MyDigest
	SignedXml.SignatureAlgorithms["http://mySigningAlgorithm"] = MySignatureAlgorithm


	function signXml(xml, xpath, key, dest)
	{
	  var sig = new SignedXml()

	  /*configure the signature object to use the custom algorithms*/
	  sig.signatureAlgorithm = "http://mySignatureAlgorithm"
	  sig.keyInfoProvider = new MyKeyInfo()
	  sig.canonicalizationAlgorithm = "http://MyCanonicalization"
	  sig.addReference("//*[local-name(.)='x']", ["http://MyTransformation"], "http://myDigestAlgorithm")

	  sig.signingKey = fs.readFileSync(key)
	  sig.addReference(xpath)    
	  sig.computeSignature(xml)
	  fs.writeFileSync(dest, sig.getSignedXml())
	}

	var xml = "<library>" +
	            "<book>" +
	              "<name>Harry Potter</name>" +
	            "</book>"
	          "</library>"

	signXml(xml, 
	  "//*[local-name(.)='book']", 
	  "client.pem", 
	  "result.xml")

You can always look at the actual code as a sample (or drop me a [mail](mailto:yaronn01@gmail.com)).


## X.509 / Key formats
Xml-Crypto internally relies on node's crypto module. This means pem encoded certificates are supported. So to sign an xml use key.pem that looks like this (only the begining of the key content is shown):

	-----BEGIN PRIVATE KEY-----
	MIICdwIBADANBgkqhkiG9w0...
	-----END PRIVATE KEY-----

And for verification use key_public.pem:

	-----BEGIN CERTIFICATE-----
	MIIBxDCCAW6gAwIBAgIQxUSX...
	-----END CERTIFICATE-----

**Converting .pfx certificates to pem**
Convert .pfx to .pem using openssl](http://www.openssl.org/):
	openssl pkcs12 -in c:\certs\yourcert.pfx -out c:\certs\cag.pem

Then you could use the result as is for the purpose of signing. For the purpose of validation open the .pem with a text editor and copy from -----BEGIN CERTIFICATE----- to  -----END CERTIFICATE----- (including) to a new .pem file.

## More information
Visit my [blog](http://webservices20.blogspot.com/) or my [twitter](http://twitter.com/#!/YaronNaveh)
