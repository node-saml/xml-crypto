import { expect } from "chai";

import { C14nCanonicalization } from "../src/c14n-canonicalization";
import * as xmldom from "@xmldom/xmldom";
import * as xpath from "xpath";
import * as utils from "../src/utils";
import * as isDomNode from "@xmldom/is-dom-node";

const test_C14nCanonicalization = function (xml, xpathArg, expected) {
  const doc = new xmldom.DOMParser().parseFromString(xml);
  const node = xpath.select1(xpathArg, doc);
  const can = new C14nCanonicalization();

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
});
