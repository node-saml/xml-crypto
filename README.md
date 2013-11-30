## xml-crypto
An xml digital signature library for node. Xml encryption is coming soon. Written in pure javascript!

For more information visit [my blog](http://webservices20.blogspot.com/) or [my twitter](https://twitter.com/YaronNaveh).

## Install
Install with [npm](http://github.com/isaacs/npm):

    npm install xml-crypto

A pre requisite it to have [openssl](http://www.openssl.org/) installed and its /bin to be on the system path. I used version 1.0.1c but it should work on older versions too.

## Signing Xml documents
Use this code:

`````javascript
	var SignedXml = require('xml-crypto').SignedXml	  
	  , fs = require('fs')

	var xml = "<library>" +
	            "<book>" +
	              "<name>Harry Potter</name>" +
	            "</book>" +
	          "</library>"

	var sig = new SignedXml()
	sig.addReference("//*[local-name(.)='book']")    
	sig.signingKey = fs.readFileSync("client.pem")
	sig.computeSignature(xml)
	fs.writeFileSync("signed.xml", sig.getSignedXml())

`````

The result will be:


`````xml
	<library>
	  <book Id="_0">
	    <name>Harry Potter</name>
	  </book>
	  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
	    <SignedInfo>
	      <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
	      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
	      <Reference URI="#_0">
	        <Transforms>
	          <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
	        </Transforms>
	        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
	        <DigestValue>cdiS43aFDQMnb3X8yaIUej3+z9Q=</DigestValue>
	      </Reference>
	    </SignedInfo>
	    <SignatureValue>vhWzpQyIYuncHUZV9W...[long base64 removed]...</SignatureValue>
	  </Signature>
	</library>
`````


Notes:

sig.getSignedXml() returns the original xml document with the signature pushed as the last child of the root node (as above). This assumes you are not signing the root node but only sub node(s) otherwise this is not valid. If you do sign the root node call sig.getSignatureXml() to get just the signature part and sig.getOriginalXmlWithIds() to get the original xml with Id attributes added on relevant elements (required for validation).

## Verifying Xml documents

You can use any dom parser you want in your code (or none, depending on your usage). This sample uses [xmldom](https://github.com/jindw/xmldom) so you should install it first:

    npm install xmldom    

Then run:

`````javascript
	var select = require('xml-crypto').xpath
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
`````

Note: 

The xml-crypto api requires you to supply it separately the xml signature ("&lt;Signature&gt;...&lt;/Signature&gt;", in loadSignature) and the signed xml (in checkSignature). The signed xml may or may not contain the signature in it, but you are still required to supply the signature separately.

## Supported Algorithms
The first release always uses the following algorithems:

* Exclusive Canonicalization http://www.w3.org/2001/10/xml-exc-c14n#
* SHA1 digests http://www.w3.org/2000/09/xmldsig#sha1
* RSA-SHA1 signature algorithm http://www.w3.org/2000/09/xmldsig#rsa-sha1

you are able to extend xml-crypto with further algorithms.

## Customizing Algorithms
The following sample shows how to sign a message using custom algorithms.

First import some modules:

`````javascript
	var SignedXml = require('xml-crypto').SignedXml
	  , fs = require('fs')
`````


Now define the extension point you want to implement. You can choose one ore more.

A key info provider is used to extract and construct the key and the KeyInfo xml section.
Implement it if you want to create a signature with a KeyInfo section, or you want to read your key in a different way then the default file read option.
`````javascript
	/**/
	function MyKeyInfo() {
	  this.getKeyInfo = function(key) {
	    return "<X509Data></X509Data>"
	  }
	  this.getKey = function(keyInfo) {
	    //you can use the keyInfo parameter to extract the key in any way you want      
	    return fs.readFileSync("key.pem")
	  }
	}
`````

A custom hash algorithm is used to calculate digests. Implement it if you want a hash other than the default SHA1.

`````javascript
	function MyDigest() {


	  this.getHash = function(xml) {    
	    return "the base64 hash representation of the given xml string"
	  }

	  this.getAlgorithmName = function() {
	    return "http://myDigestAlgorithm"
	  }
	}
`````

A custom signing algorithm. The default is RSA-SHA1
`````javascript	
	function MySignatureAlgorithm() {

	  /*sign the given SignedInfo using the key. return base64 signature value*/
	  this.getSignature = function(signedInfo, signingKey) {            
	    return "signature of signedInfo as base64..."
	  }

	  this.getAlgorithmName = function() {
	    return "http://mySigningAlgorithm"
	  }

	}
`````

Custom transformation algorithm. The default is exclusive canonicalization.

`````javascript	
	function MyTransformation() {
	  
	  /*given a node (from the xmldom module) return its canonical representation (as string)*/
	  this.process = function(node) {	  	
	  	//you should apply your transformation before returning
	    return node.toString()
	  }

	  this.getAlgorithmName = function() {
	    return "http://myTransformation"
	  }
	}
`````
Custom canonicalization is actually the same as custom transformation. It is applied on the SignedInfo rather than on references.

`````javascript
	function MyCanonicalization() {

	  /*given a node (from the xmldom module) return its canonical representation (as string)*/
	  this.process = function(node) {
	    //you should apply your transformation before returning
	    return "< x/>"
	  }

	   this.getAlgorithmName = function() {
	    return "http://myCanonicalization"
	  }
	}
`````

Now you need to register the new algorithms:

`````javascript
	/*register all the custom algorithms*/

	SignedXml.CanonicalizationAlgorithms["http://MyTransformation"] = MyTransformation
	SignedXml.CanonicalizationAlgorithms["http://MyCanonicalization"] = MyCanonicalization
	SignedXml.HashAlgorithms["http://myDigestAlgorithm"] = MyDigest
	SignedXml.SignatureAlgorithms["http://mySigningAlgorithm"] = MySignatureAlgorithm
`````

Now do the signing. Note how we configure the signature to use the above algorithms:

`````javascript
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
`````

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

If you have .pfx certificates you can convert them to .pem using [openssl](http://www.openssl.org/):

	openssl pkcs12 -in c:\certs\yourcert.pfx -out c:\certs\cag.pem

Then you could use the result as is for the purpose of signing. For the purpose of validation open the resulting .pem with a text editor and copy from -----BEGIN CERTIFICATE----- to  -----END CERTIFICATE----- (including) to a new text file and save it as .pem.

## Development
The test framework is [nodeunit](https://github.com/caolan/nodeunit). To run tests use:

    $> npm test

## More information
Visit my [blog](http://webservices20.blogspot.com/) or my [twitter](http://twitter.com/#!/YaronNaveh)


[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/yaronn/xml-crypto/trend.png)](https://bitdeli.com/free "Bitdeli Badge")

