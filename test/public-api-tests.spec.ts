import { expect } from "chai";
import * as xmlCrypto from "../src/index";

/**
 * The published surface used to grow by accident: `index.ts` re-exported `./utils` with
 * `export *`, so adding a helper for `signed-xml.ts` to use published it too. The list is
 * explicit now, and this test makes widening it a deliberate edit rather than a side effect.
 *
 * Only runtime values can be checked here — types are erased, but they can only reach the
 * surface by being named in `index.ts`, which is a reviewable diff on its own.
 *
 * @see https://github.com/node-saml/xml-crypto/issues/551
 */
const PUBLIC_EXPORTS = [
  "C14nCanonicalization",
  "C14nCanonicalizationWithComments",
  "ExclusiveCanonicalization",
  "ExclusiveCanonicalizationWithComments",
  "SignedXml",
  "createOptionalCallbackFunction",
  "derToPem",
  "findAncestorNs",
  "normalizePem",
  "pemToDer",
];

describe("Public API surface", function () {
  it("exports exactly the documented names", function () {
    expect(Object.keys(xmlCrypto).sort()).to.deep.equal(PUBLIC_EXPORTS);
  });

  /**
   * `index.ts` only decides what the barrel re-exports. Without an `exports` map every file
   * under `lib/` is reachable by path too, and consumers do reach for it, so the entry points
   * are pinned here as well.
   */
  it("declares only the package entry point and package.json as subpaths", function () {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const manifest = require("../package.json");

    expect(Object.keys(manifest.exports)).to.deep.equal([".", "./package.json"]);
    expect(manifest.exports["."]).to.deep.equal({
      types: "./lib/index.d.ts",
      default: "./lib/index.js",
    });
  });
});
