import { expect } from "chai";

import {
  C14nCanonicalization,
  C14nCanonicalizationWithComments,
} from "../src/c14n-canonicalization";
import * as xmldom from "@xmldom/xmldom";
import * as xpath from "xpath";
import * as utils from "../src/utils";
import * as isDomNode from "@xmldom/is-dom-node";

const test_C14nCanonicalization = function (
  xml: string,
  xpathArg: string,
  expected: string,
  can = new C14nCanonicalization(),
) {
  const doc = new xmldom.DOMParser().parseFromString(xml);
  const node = xpath.select1(xpathArg, doc);

  isDomNode.assertIsNodeLike(node);
  const result = can
    .process(node, {
      ancestorNamespaces: utils.findAncestorNs(doc, xpathArg),
    })
    .toString();

  expect(result).to.equal(expected);
};

const test_findAncestorNs = function (xml, xpath, expected) {
  const doc = new xmldom.DOMParser().parseFromString(xml);
  const result = utils.findAncestorNs(doc, xpath);

  expect(result).to.deep.equal(expected);
};

describe("C14N non-exclusive canonicalization tests", function () {
  it("findAncestorNs: Correctly picks up root ancestor namespace", function () {
    const xml = "<root xmlns:aaa='bbb'><child1><child2></child2></child1></root>";
    const xpath = "/root/child1/child2";
    const expected = [{ prefix: "aaa", namespaceURI: "bbb" }];

    test_findAncestorNs(xml, xpath, expected);
  });

  it("findAncestorNs: Correctly picks up intermediate ancestor namespace", function () {
    const xml = "<root><child1 xmlns:aaa='bbb'><child2></child2></child1></root>";
    const xpath = "/root/child1/child2";
    const expected = [{ prefix: "aaa", namespaceURI: "bbb" }];

    test_findAncestorNs(xml, xpath, expected);
  });

  it("findAncestorNs: Correctly picks up multiple ancestor namespaces declared in the one same element", function () {
    const xml = "<root xmlns:aaa='bbb' xmlns:ccc='ddd'><child1><child2></child2></child1></root>";
    const xpath = "/root/child1/child2";
    const expected = [
      { prefix: "aaa", namespaceURI: "bbb" },
      { prefix: "ccc", namespaceURI: "ddd" },
    ];

    test_findAncestorNs(xml, xpath, expected);
  });

  it("findAncestorNs: Correctly picks up multiple ancestor namespaces scattered among depth", function () {
    const xml = "<root xmlns:aaa='bbb'><child1 xmlns:ccc='ddd'><child2></child2></child1></root>";
    const xpath = "/root/child1/child2";
    const expected = [
      { prefix: "ccc", namespaceURI: "ddd" },
      { prefix: "aaa", namespaceURI: "bbb" },
    ];

    test_findAncestorNs(xml, xpath, expected);
  });

  it("findAncestorNs: Correctly picks up multiple ancestor namespaces without duplicate", function () {
    const xml = "<root xmlns:ccc='bbb'><child1 xmlns:ccc='bbb'><child2></child2></child1></root>";
    const xpath = "/root/child1/child2";
    const expected = [{ prefix: "ccc", namespaceURI: "bbb" }];

    test_findAncestorNs(xml, xpath, expected);
  });

  it("findAncestorNs: Correctly eliminates duplicate prefix", function () {
    const xml = "<root xmlns:ccc='bbb'><child1 xmlns:ccc='AAA'><child2></child2></child1></root>";
    const xpath = "/root/child1/child2";
    const expected = [{ prefix: "ccc", namespaceURI: "AAA" }];

    test_findAncestorNs(xml, xpath, expected);
  });

  it("findAncestorNs: Exclude namespace which is already declared with same prefix on target node", function () {
    const xml =
      "<root xmlns:ccc='bbb'><child1 xmlns:ccc='AAA'><child2 xmlns:ccc='AAA'></child2></child1></root>";
    const xpath = "/root/child1/child2";
    const expected = [];

    test_findAncestorNs(xml, xpath, expected);
  });

  it("findAncestorNs: Ignores namespace declared in the target xpath node", function () {
    const xml = "<root xmlns:aaa='bbb'><child1><child2 xmlns:ccc='ddd'></child2></child1></root>";
    const xpath = "/root/child1/child2";
    const expected = [{ prefix: "aaa", namespaceURI: "bbb" }];

    test_findAncestorNs(xml, xpath, expected);
  });

  it("findAncestorNs: Should find namespace without prefix", function () {
    const xml =
      "<root xmlns='bbb'><child1><ds:child2 xmlns:ds='ddd'><ds:child3></ds:child3></ds:child2></child1></root>";
    const xpath = "//*[local-name()='child2']";
    const expected = [{ prefix: "", namespaceURI: "bbb" }];

    test_findAncestorNs(xml, xpath, expected);
  });

  it("findAncestorNs: Should not find namespace when both has no prefix", function () {
    const xml = "<root xmlns='bbb'><child1><child2 xmlns='ddd'></child2></child1></root>";
    const xpath = "//*[local-name()='child2']";
    const expected = [];

    test_findAncestorNs(xml, xpath, expected);
  });

  it("findAncestorNs: Should not hoist default namespace when subset also declares a prefixed namespace", function () {
    // The element's own default namespace must be rendered only once.
    // https://www.w3.org/TR/2001/REC-xml-c14n-20010315#ProcessingModel
    const xml = '<root xmlns="urn:default"><child1><child2 xmlns:enc="urn:enc"/></child1></root>';
    const xpath = "//*[local-name()='child2']";
    const expected = [];

    test_findAncestorNs(xml, xpath, expected);
  });

  it("findAncestorNs: Should hoist non-default ancestor namespaces when subset is in default namespace", function () {
    // Inclusive C14N retains ancestor bindings even when the subset does not visibly use them.
    // https://www.w3.org/TR/2001/REC-xml-c14n-20010315#DataModel
    const xml =
      '<root xmlns="urn:default" xmlns:aaa="urn:aaa"><child1><child2 xmlns:enc="urn:enc"/></child1></root>';
    const xpath = "//*[local-name()='child2']";
    const expected = [{ prefix: "aaa", namespaceURI: "urn:aaa" }];

    test_findAncestorNs(xml, xpath, expected);
  });

  it("findAncestorNs: Should not suppress ancestor namespace for non-namespace attribute starting with 'xmlns'", function () {
    // Only xmlns and xmlns:* declare namespaces; xmlnsfoo must not hide an inherited binding.
    // https://www.w3.org/TR/REC-xml-names/#ns-decl
    const xml = '<root xmlns:foo="urn:foo"><child1><child2 xmlnsfoo="bar"/></child1></root>';
    const xpath = "//*[local-name()='child2']";
    const expected = [{ prefix: "foo", namespaceURI: "urn:foo" }];

    test_findAncestorNs(xml, xpath, expected);
  });

  for (const { label, subsetXpath } of [
    { label: "attributes", subsetXpath: "//@attr" },
    { label: "text nodes", subsetXpath: "//*[local-name()='child']/text()" },
  ]) {
    it(`findAncestorNs: Should reject a document subset of ${label}`, function () {
      // Only elements carry namespace declarations. Without this check the
      // non-element reaches findSubsetNSPrefixes, whose `.attributes` is null
      // there, and the caller gets a TypeError instead of a usable message.
      const xml = "<root xmlns:anc='urn:ancestor'><child attr='value'>text</child></root>";
      const doc = new xmldom.DOMParser().parseFromString(xml);

      expect(() => utils.findAncestorNs(doc, subsetXpath)).to.throw(
        "Document subset must be list of elements",
      );
    });
  }

  // Tests for c14nCanonicalization
  it("C14n: Correctly picks up root ancestor namespace", function () {
    const xml = "<root xmlns:aaa='bbb'><child1><child2></child2></child1></root>";
    const xpath = "/root/child1/child2";
    const expected = '<child2 xmlns:aaa="bbb"></child2>';

    test_C14nCanonicalization(xml, xpath, expected);
  });

  it("C14n: Correctly picks up intermediate ancestor namespace", function () {
    const xml = "<root><child1 xmlns:aaa='bbb'><child2></child2></child1></root>";
    const xpath = "/root/child1/child2";
    const expected = '<child2 xmlns:aaa="bbb"></child2>';

    test_C14nCanonicalization(xml, xpath, expected);
  });

  it("C14n: Correctly picks up multiple ancestor namespaces declared in the one same element", function () {
    const xml = "<root xmlns:aaa='bbb' xmlns:ccc='ddd'><child1><child2></child2></child1></root>";
    const xpath = "/root/child1/child2";
    const expected = '<child2 xmlns:aaa="bbb" xmlns:ccc="ddd"></child2>';

    test_C14nCanonicalization(xml, xpath, expected);
  });

  it("C14n: Correctly picks up multiple ancestor namespaces scattered among depth", function () {
    const xml = "<root xmlns:aaa='bbb'><child1 xmlns:ccc='ddd'><child2></child2></child1></root>";
    const xpath = "/root/child1/child2";
    const expected = '<child2 xmlns:aaa="bbb" xmlns:ccc="ddd"></child2>';

    test_C14nCanonicalization(xml, xpath, expected);
  });

  it("C14n: Correctly picks up multiple ancestor namespaces without duplicate", function () {
    const xml = "<root xmlns:ccc='bbb'><child1 xmlns:ccc='bbb'><child2></child2></child1></root>";
    const xpath = "/root/child1/child2";
    const expected = '<child2 xmlns:ccc="bbb"></child2>';

    test_C14nCanonicalization(xml, xpath, expected);
  });

  it("C14n: Correctly eliminates duplicate prefix", function () {
    const xml = "<root xmlns:ccc='bbb'><child1 xmlns:ccc='AAA'><child2></child2></child1></root>";
    const xpath = "/root/child1/child2";
    const expected = '<child2 xmlns:ccc="AAA"></child2>';

    test_C14nCanonicalization(xml, xpath, expected);
  });

  it("C14n: Exclude namespace which is already declared with same prefix on target node", function () {
    const xml =
      "<root xmlns:ccc='bbb'><child1 xmlns:ccc='AAA'><child2 xmlns:ccc='AAA'></child2></child1></root>";
    const xpath = "/root/child1/child2";
    const expected = '<child2 xmlns:ccc="AAA"></child2>';

    test_C14nCanonicalization(xml, xpath, expected);
  });

  it("C14n: Preserve namespace declared in the target xpath node", function () {
    const xml = '<root xmlns:aaa="bbb"><child1><child2 xmlns:ccc="ddd"></child2></child1></root>';
    const xpath = "/root/child1/child2";
    const expected = '<child2 xmlns:aaa="bbb" xmlns:ccc="ddd"></child2>';

    test_C14nCanonicalization(xml, xpath, expected);
  });

  it("C14n: Don't redeclare an attribute's namespace prefix if already in scope", function () {
    const xml =
      "<root xmlns:aaa='bbb'><child1><child2 xmlns:aaa='bbb' aaa:foo='bar'></child2></child1></root>";
    const xpath = "/root/child1/child2";
    const expected = '<child2 xmlns:aaa="bbb" aaa:foo="bar"></child2>';

    test_C14nCanonicalization(xml, xpath, expected);
  });

  it("C14n: Don't declare an attribute's namespace prefix if in scope from parent", function () {
    const xml =
      "<root xmlns:aaa='bbb'><child1><child2><child3 aaa:foo='bar'></child3></child2></child1></root>";
    const xpath = "/root/child1";
    const expected =
      '<child1 xmlns:aaa="bbb"><child2><child3 aaa:foo="bar"></child3></child2></child1>';

    test_C14nCanonicalization(xml, xpath, expected);
  });

  it("C14n: should not has colon when parent namespace has no prefix", function () {
    const xml =
      "<root xmlns='bbb'><child1><cc:child2 xmlns:cc='ddd'><cc:child3></cc:child3></cc:child2></child1></root>";
    const xpath = "//*[local-name()='child3']";
    const expected = '<cc:child3 xmlns="bbb" xmlns:cc="ddd"></cc:child3>';

    test_C14nCanonicalization(xml, xpath, expected);
  });

  for (const Canonicalization of [C14nCanonicalization, C14nCanonicalizationWithComments]) {
    describe(`${Canonicalization.name}: hoisted ancestor namespaces`, function () {
      // A hoisted ancestor default namespace becomes the default the subset's descendants are
      // canonicalized against. The rationale is spelled out in §4.7: the empty default is kept on
      // output "so that e3 does not take on the default namespace qualification of e1".
      // https://www.w3.org/TR/xml-c14n/#ProcessingModel
      // https://www.w3.org/TR/xml-c14n/#PropagateDefaultNSDecl
      it('renders xmlns="" on a descendant when the apex hoists an ancestor default namespace', function () {
        test_C14nCanonicalization(
          '<root xmlns="urn:A"><p:x xmlns:p="urn:p"><y xmlns=""></y></p:x></root>',
          "//*[local-name()='x']",
          '<p:x xmlns="urn:A" xmlns:p="urn:p"><y xmlns=""></y></p:x>',
          new Canonicalization(),
        );
      });

      it("omits a descendant declaration the hoisted ancestor default namespace makes redundant", function () {
        test_C14nCanonicalization(
          '<root xmlns="urn:A"><p:x xmlns:p="urn:p"><y xmlns="urn:A"></y></p:x></root>',
          "//*[local-name()='x']",
          '<p:x xmlns="urn:A" xmlns:p="urn:p"><y></y></p:x>',
          new Canonicalization(),
        );
      });

      it("renders the hoisted ancestor default namespace once when the apex inherits it", function () {
        test_C14nCanonicalization(
          '<root xmlns="urn:A"><x xmlns:p="urn:p"><y xmlns=""></y></x></root>',
          "//*[local-name()='x']",
          '<x xmlns="urn:A" xmlns:p="urn:p"><y xmlns=""></y></x>',
          new Canonicalization(),
        );
      });

      it("prefers the apex's own default namespace over the hoisted ancestor one", function () {
        test_C14nCanonicalization(
          '<root xmlns="urn:A"><x xmlns:p="urn:p" xmlns="urn:B"><y></y></x></root>',
          "//*[local-name()='x']",
          '<x xmlns="urn:B" xmlns:p="urn:p"><y></y></x>',
          new Canonicalization(),
        );
      });

      // A declaration on the apex shadows the ancestor one binding the same prefix, so the
      // element must not resolve against the outer binding — in its descendants or its own name.
      // https://www.w3.org/TR/REC-xml-names/#scoping
      it("renders the apex's redeclaration of an ancestor prefix, not the ancestor binding", function () {
        test_C14nCanonicalization(
          '<root xmlns:q="urn:old"><x xmlns:p="urn:p" xmlns:q="urn:new"><q:y></q:y></x></root>',
          "//*[local-name()='x']",
          '<x xmlns:p="urn:p" xmlns:q="urn:new"><q:y></q:y></x>',
          new Canonicalization(),
        );
      });

      it("renders the apex's redeclaration of the prefix in its own name", function () {
        test_C14nCanonicalization(
          '<root xmlns:q="urn:old"><q:x xmlns:p="urn:p" xmlns:q="urn:new"><y></y></q:x></root>',
          "//*[local-name()='x']",
          '<q:x xmlns:p="urn:p" xmlns:q="urn:new"><y></y></q:x>',
          new Canonicalization(),
        );
      });
    });

    describe(`${Canonicalization.name}: subset namespace declarations`, function () {
      it("does not duplicate the default namespace when the subset declares a prefixed namespace", function () {
        // Render the inherited default namespace exactly once on the subset root.
        // https://www.w3.org/TR/2001/REC-xml-c14n-20010315#ProcessingModel
        test_C14nCanonicalization(
          '<root xmlns="urn:default"><child1><child2 xmlns:enc="urn:enc"/></child1></root>',
          "//*[local-name()='child2']",
          '<child2 xmlns="urn:default" xmlns:enc="urn:enc"></child2>',
          new Canonicalization(),
        );
      });

      it("does not duplicate the default namespace for the reported #538 document", function () {
        // Literal reproduction from https://github.com/node-saml/xml-crypto/issues/538:
        // a subset root inheriting a default namespace while declaring a prefixed one,
        // with a prefixed child that must resolve against the local declaration.
        // https://www.w3.org/TR/2001/REC-xml-c14n-20010315#ProcessingModel
        test_C14nCanonicalization(
          '<Root xmlns="http://example.com/root">' +
            '<Body Id="B" xmlns:enc="http://www.w3.org/2001/04/xmlenc#">' +
            "<enc:CipherValue>x</enc:CipherValue></Body></Root>",
          "//*[local-name()='Body']",
          '<Body xmlns="http://example.com/root" xmlns:enc="http://www.w3.org/2001/04/xmlenc#" Id="B">' +
            "<enc:CipherValue>x</enc:CipherValue></Body>",
          new Canonicalization(),
        );
      });

      it("retains unused ancestor prefixes alongside the default and local namespaces", function () {
        // Inclusive C14N preserves every in-scope namespace, including unused ancestor bindings.
        // https://www.w3.org/TR/2001/REC-xml-c14n-20010315#DataModel
        test_C14nCanonicalization(
          '<root xmlns="urn:default" xmlns:aaa="urn:aaa"><child2 xmlns:enc="urn:enc"/></root>',
          "//*[local-name()='child2']",
          '<child2 xmlns="urn:default" xmlns:aaa="urn:aaa" xmlns:enc="urn:enc"></child2>',
          new Canonicalization(),
        );
      });

      for (const declarations of [
        'xmlns:a="urn:local-a" xmlns:b="urn:local-b"',
        'xmlns:b="urn:local-b" xmlns:a="urn:local-a"',
      ]) {
        it(`uses both local prefix bindings with ${declarations}`, function () {
          // Local declarations override ancestor bindings regardless of declaration order.
          // https://www.w3.org/TR/2001/REC-xml-c14n-20010315#DataModel
          test_C14nCanonicalization(
            '<root xmlns:a="urn:ancestor-a" xmlns:b="urn:ancestor-b">' +
              `<child2 ${declarations}><a:item/><b:item/></child2></root>`,
            "//*[local-name()='child2']",
            '<child2 xmlns:a="urn:local-a" xmlns:b="urn:local-b"><a:item></a:item><b:item></b:item></child2>',
            new Canonicalization(),
          );
        });
      }

      it("renders the default namespace on a prefixed apex that redeclares it", function () {
        // Every namespace in scope at the apex is rendered there, including the default one.
        // https://www.w3.org/TR/2001/REC-xml-c14n-20010315#ProcessingModel
        test_C14nCanonicalization(
          '<root xmlns="urn:default"><p:child2 xmlns:p="urn:p" xmlns="urn:default"/></root>',
          "//*[local-name()='child2']",
          '<p:child2 xmlns="urn:default" xmlns:p="urn:p"></p:child2>',
          new Canonicalization(),
        );
      });

      it("omits a descendant default namespace already hoisted onto the subset root", function () {
        // https://www.w3.org/TR/2001/REC-xml-c14n-20010315#ProcessingModel
        test_C14nCanonicalization(
          '<root xmlns="urn:default" xmlns:p="urn:p">' +
            '<p:target><p:child xmlns="urn:default"/></p:target></root>',
          "//*[local-name()='target']",
          '<p:target xmlns="urn:default" xmlns:p="urn:p"><p:child></p:child></p:target>',
          new Canonicalization(),
        );
      });

      it("does not restore a default namespace explicitly cleared on a prefixed root", function () {
        // An empty default declaration removes the inherited binding; no reset is needed at the apex.
        // https://www.w3.org/TR/REC-xml-names/#defaulting
        // https://www.w3.org/TR/2001/REC-xml-c14n-20010315#ProcessingModel
        test_C14nCanonicalization(
          '<root xmlns="urn:ancestor"><p:child2 xmlns:p="urn:p" xmlns=""><item/></p:child2></root>',
          "//*[local-name()='child2']",
          '<p:child2 xmlns:p="urn:p"><item></item></p:child2>',
          new Canonicalization(),
        );
      });
    });
  }
});
