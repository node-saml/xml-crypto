import { expect } from "chai";
import * as xmldom from "@xmldom/xmldom";
import * as isDomNode from "@xmldom/is-dom-node";
import {
  C14nCanonicalization,
  C14nCanonicalizationWithComments,
  ExclusiveCanonicalization,
  ExclusiveCanonicalizationWithComments,
} from "../src/index";

// Namespace nodes sort by local name (the prefix), attributes by namespace URI then local
// name, each compared by code point: https://www.w3.org/TR/xml-c14n#DocumentOrder
const canonicalize = (Canonicalization, xml: string) => {
  const root = new xmldom.DOMParser().parseFromString(xml, "text/xml").documentElement;
  isDomNode.assertIsElementNode(root);
  return new Canonicalization().process(root, {});
};

describe("Canonical order of namespace declarations and attributes", function () {
  for (const Canonicalization of [
    C14nCanonicalization,
    C14nCanonicalizationWithComments,
    ExclusiveCanonicalization,
    ExclusiveCanonicalizationWithComments,
  ]) {
    describe(Canonicalization.name, function () {
      it("orders namespace prefixes by code point, not by locale", function () {
        expect(
          canonicalize(
            Canonicalization,
            '<SOAP-ENV:Envelope xmlns:ds="urn:d" xmlns:SOAP-ENV="urn:s" ds:a="1"/>',
          ),
        ).to.equal(
          '<SOAP-ENV:Envelope xmlns:SOAP-ENV="urn:s" xmlns:ds="urn:d" ds:a="1"></SOAP-ENV:Envelope>',
        );
        expect(
          canonicalize(Canonicalization, '<B:r xmlns:a="urn:2" xmlns:B="urn:1" a:x="1"/>'),
        ).to.equal('<B:r xmlns:B="urn:1" xmlns:a="urn:2" a:x="1"></B:r>');
      });

      it("orders the default namespace before prefixed ones", function () {
        expect(
          canonicalize(Canonicalization, '<r xmlns:A="urn:a" xmlns="urn:d" A:x="1"/>'),
        ).to.equal('<r xmlns="urn:d" xmlns:A="urn:a" A:x="1"></r>');
      });

      it("orders attributes by namespace URI before local name", function () {
        expect(
          canonicalize(Canonicalization, '<r xmlns:p="urn:a" xmlns:q="urn:az" q:a="2" p:zb="1"/>'),
        ).to.equal('<r xmlns:p="urn:a" xmlns:q="urn:az" p:zb="1" q:a="2"></r>');
      });

      it("orders attributes without a namespace first, by local name", function () {
        expect(canonicalize(Canonicalization, '<r xmlns:p="urn:a" p:a="3" b="2" a="1"/>')).to.equal(
          '<r xmlns:p="urn:a" a="1" b="2" p:a="3"></r>',
        );
      });

      it("orders namespace URIs outside the BMP by code point, not by UTF-16 code unit", function () {
        expect(
          canonicalize(
            Canonicalization,
            '<r xmlns:p="urn:\u{10000}" xmlns:q="urn:\uF900" p:a="2" q:a="1"/>',
          ),
        ).to.equal('<r xmlns:p="urn:\u{10000}" xmlns:q="urn:\uF900" q:a="1" p:a="2"></r>');
      });
    });
  }
});
