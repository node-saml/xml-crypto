import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import { expect } from "chai";
import * as xmlCrypto from "../src/index";

/**
 * Each of these is withdrawn in 7.0, so a consumer needs a warning from 6.x first. The pairs are
 * the exported name and the `code` its warning carries.
 *
 * @see https://github.com/node-saml/xml-crypto/issues/551
 */
function element(): Element {
  const doc = new xmldom.DOMParser().parseFromString("<root><a/></root>", "text/xml");
  const root = doc.documentElement;
  if (root == null) {
    throw new Error("could not parse the fixture");
  }
  return root;
}

// Naming these is the point of the test, so the rule that forbids naming them is off here.
/* eslint-disable deprecation/deprecation */
const DEPRECATED_FUNCTIONS = [
  ["isArrayHasLength", "XML_CRYPTO_IS_ARRAY_HAS_LENGTH", () => xmlCrypto.isArrayHasLength([1])],
  ["findAttr", "XML_CRYPTO_FIND_ATTR", () => xmlCrypto.findAttr(element(), "attr")],
  ["findChildren", "XML_CRYPTO_FIND_CHILDREN", () => xmlCrypto.findChildren(element(), "a")],
  ["findChilds", "XML_CRYPTO_FIND_CHILDS", () => xmlCrypto.findChilds(element(), "a")],
  [
    "isDescendantOf",
    "XML_CRYPTO_IS_DESCENDANT_OF",
    () => xmlCrypto.isDescendantOf(element(), element()),
  ],
  [
    "encodeSpecialCharactersInAttribute",
    "XML_CRYPTO_ENCODE_SPECIAL_CHARACTERS_IN_ATTRIBUTE",
    () => xmlCrypto.encodeSpecialCharactersInAttribute("a&b"),
  ],
  [
    "encodeSpecialCharactersInText",
    "XML_CRYPTO_ENCODE_SPECIAL_CHARACTERS_IN_TEXT",
    () => xmlCrypto.encodeSpecialCharactersInText("a&b"),
  ],
  [
    "validateDigestValue",
    "XML_CRYPTO_VALIDATE_DIGEST_VALUE",
    () => xmlCrypto.validateDigestValue("YQ==", "YQ=="),
  ],
] as const;
/* eslint-enable deprecation/deprecation */

/** `util.deprecate` warns once per wrapped function, so capture around the very first call. */
function warningsFrom(call: () => unknown): { message: string; code?: string }[] {
  const captured: { message: string; code?: string }[] = [];
  const emitWarning = process.emitWarning;
  process.emitWarning = ((message: string | Error, _type?: unknown, code?: unknown) => {
    captured.push({
      message: String(message),
      code: typeof code === "string" ? code : undefined,
    });
  }) as typeof process.emitWarning;

  try {
    call();
  } finally {
    process.emitWarning = emitWarning;
  }

  return captured;
}

describe("Deprecated exports", function () {
  DEPRECATED_FUNCTIONS.forEach(([name, code, call]) => {
    it(`warns that ${name}() is going away, naming what to use instead`, function () {
      const warnings = warningsFrom(call);

      expect(warnings, `expected ${name}() to warn on first call`).to.have.lengthOf(1);
      expect(warnings[0].code).to.equal(code);
      expect(warnings[0].message).to.contain("will be removed in version 7.0");
      expect(warnings[0].message).to.contain("instead");
      for (const [other] of DEPRECATED_FUNCTIONS) {
        if (other !== name) {
          expect(
            warnings[0].message,
            `${name}() points at ${other}(), which is going away too`,
          ).to.not.match(new RegExp(`\\b${other}\\b`));
        }
      }
    });
  });

  it("does not warn on the library's own code paths", function () {
    const xml = fs.readFileSync("./test/static/valid_signature.xml", "utf8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const signature = new xmlCrypto.SignedXml().findSignatures(doc)[0];

    const warnings = warningsFrom(() => {
      const sig = new xmlCrypto.SignedXml({
        publicCert: fs.readFileSync("./test/static/client_public.pem"),
      });
      sig.loadSignature(signature);
      expect(sig.checkSignature(xml)).to.be.true;
    });

    // `signed-xml.ts` reaches these helpers as `utils.x`, which is not the wrapped export.
    expect(warnings.filter((warning) => warning.code?.startsWith("XML_CRYPTO_"))).to.deep.equal([]);
  });

  it("keeps the export surface identical, so nothing breaks yet", function () {
    for (const name of DEPRECATED_FUNCTIONS.map(([exportName]) => exportName)) {
      expect(xmlCrypto, name).to.have.property(name);
    }
    for (const name of ["PEM_FORMAT_REGEX", "EXTRACT_X509_CERTS", "BASE64_REGEX"] as const) {
      /* eslint-disable-next-line deprecation/deprecation */
      expect(xmlCrypto[name], name).to.be.instanceOf(RegExp);
    }
  });
});
