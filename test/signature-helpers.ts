import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import { SignedXml } from "../src/index";

export const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
export const inclusiveC14n = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
export const sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
export const rsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

export function verifySignature(xml: string) {
  const verifier = new SignedXml({
    publicCert: fs.readFileSync("./test/static/client_public.pem"),
  });
  verifier.loadSignature(verifier.findSignatures(new xmldom.DOMParser().parseFromString(xml))[0]);
  return {
    valid: verifier.checkSignature(xml),
    signedReferences: verifier.getSignedReferences(),
  };
}
