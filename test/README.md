# Test fixtures

This records who signed these fixtures in `static/`. One signed by another XML-DSig implementation checks interoperability rather than only this library's agreement with itself.

- `hmac_signature.xml` and `hmac.key`: signed with the JDK's `javax.xml.crypto.dsig`.
- `inclusive_namespaces_exc_c14n.xml`, `inclusive_namespaces_exc_c14n_with_comments.xml`, `inclusive_namespaces_enveloped_signature_after_exc_c14n.xml`, `inclusive_namespaces_on_second_of_two_exc_c14n.xml` and `inclusive_namespaces_after_custom_transform.xml`: signed with .NET's `System.Security.Cryptography.Xml.SignedXml` and `client.pem`.
- `inclusive_namespaces_prefix_list_with_tab.xml`: its document and reference digest come from .NET's `SignedXml`. Its `SignedInfo` was canonicalized with libxml2 and signed with openssl and `client.pem`.
- `inclusive_namespaces_in_with_comments_namespace.xml`: signed with xml-crypto 6.3.2 and `client.pem`. It checks that a signature from 6.3.2 or earlier still verifies, not interoperability. Those releases wrote a reference's `InclusiveNamespaces` under every `Transform`, in a namespace named after that Transform's `Algorithm`.
- `windows_store_signature.xml` and `windows_store_certificate.pem`: a Windows Store app receipt and the certificate that verifies it.
