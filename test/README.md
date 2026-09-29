# Test fixtures

These fixtures in `static/` were signed by other XML-DSig implementations, so the tests that use them check interoperability rather than only this library's agreement with itself. This library can't regenerate them.

- `dotnet_inclusive_namespaces_*.xml`: signed with .NET's `System.Security.Cryptography.Xml.SignedXml` and `client.pem`.
- `hmac_signature.xml` and `hmac.key`: signed with the JDK's `javax.xml.crypto.dsig`.
- `inclusive_namespaces_in_with_comments_namespace.xml`: signed with xml-crypto 6.3.2 and `client.pem`. That release wrote a reference's `InclusiveNamespaces` in the `#WithComments` namespace and under every `Transform`, which the current signer no longer does.
- `windows_store_signature.xml` and `windows_store_certificate.pem`: a Windows Store app receipt and the certificate that verifies it.
