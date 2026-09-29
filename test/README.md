# Test fixtures

These fixtures in `static/` were signed by other XML-DSig implementations, so the tests that use them check interoperability rather than only this library's agreement with itself. This library can't regenerate them.

- `hmac_signature.xml` and `hmac.key`: signed with the JDK's `javax.xml.crypto.dsig`.
- `windows_store_signature.xml` and `windows_store_certificate.pem`: a Windows Store app receipt and the certificate that verifies it.
