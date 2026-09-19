import * as crypto from "crypto";
import * as fs from "fs";
import * as utils from "../src/utils";
import { expect } from "chai";
import * as xmldom from "@xmldom/xmldom";
import * as xpath from "xpath";
import * as isDomNode from "@xmldom/is-dom-node";

describe("Utils tests", function () {
  describe("toPem", function () {
    it("will return a normalized PEM format when given an non-normalized PEM format", function () {
      const normalizedPem = fs.readFileSync("./test/static/client_public.pem", "latin1");
      const pemAsArray = normalizedPem.trim().split("\n");
      const base64String = pemAsArray.slice(1, -1).join("");
      const nonNormalizedPem = `${pemAsArray[0]}\n${base64String}\n${
        pemAsArray[pemAsArray.length - 1]
      }`;

      expect(utils.toPem(nonNormalizedPem)).to.equal(normalizedPem);
    });

    for (const eol of ["\r\n", "\r"]) {
      it(`will return a normalized PEM format when given a PEM with ${JSON.stringify(eol)} line endings`, function () {
        const normalizedPem = fs.readFileSync("./test/static/client_public.pem", "latin1");

        expect(utils.toPem(normalizedPem.replace(/\n/g, eol))).to.equal(normalizedPem);
      });
    }

    it("will return a normalized PEM format when given a base64 string", function () {
      const normalizedPem = fs.readFileSync("./test/static/client_public.pem", "latin1");
      const pemAsArray = normalizedPem.trim().split("\n");
      const base64String = pemAsArray.slice(1, -1).join("");

      expect(utils.toPem(base64String, "CERTIFICATE")).to.equal(normalizedPem);
    });

    it("will throw if the format is neither PEM nor DER", function () {
      expect(() => utils.toPem("not a pem")).to.throw();
    });

    it("will return a normalized PEM format when given a DER Buffer", function () {
      const normalizedPem = fs.readFileSync("./test/static/client_public.pem", "latin1");
      const derBuffer = fs.readFileSync("./test/static/client_public.der");

      expect(utils.toPem(derBuffer, "CERTIFICATE")).to.equal(normalizedPem);
    });

    it("will return a normalized PEM format when given a base64 string with line breaks", function () {
      const normalizedPem = fs.readFileSync("./test/static/client_public.pem", "latin1");
      const base64String = fs.readFileSync("./test/static/client_public.der", "base64");

      expect(utils.toPem(base64String, "CERTIFICATE")).to.equal(normalizedPem);
    });

    it("will return a normalized PEM format when given a base64 string with line breaks and spaces at the line breaks", function () {
      const xml = new xmldom.DOMParser().parseFromString(
        fs.readFileSync("./test/static/keyinfo - pretty-printed.xml", "latin1"),
      );
      const cert = xpath.select1(".//*[local-name(.)='X509Certificate']", xml);
      isDomNode.assertIsNodeLike(cert);

      const normalizedPem = fs.readFileSync("./test/static/keyinfo.pem", "latin1");

      expect(utils.toPem(cert.textContent ?? "", "CERTIFICATE")).to.equal(normalizedPem);
    });

    it("will throw if the DER string is not base64 encoded", function () {
      expect(() => utils.toPem("not base64", "CERTIFICATE")).to.throw();
    });

    it("will throw if the PEM label is not provided", function () {
      const derBuffer = fs.readFileSync("./test/static/client_public.der");
      expect(() => utils.toPem(derBuffer)).to.throw();
    });

    describe("judges the same data with and without encapsulation boundaries", function () {
      // These are rules for base64, so they are held to a label whose data Node does not parse:
      // under CERTIFICATE the data must also be a certificate, which none of these is.
      const wrap = (data: string) => `-----BEGIN PKCS7-----\n${data}\n-----END PKCS7-----`;

      const accepted = {
        "a whole quantum": "QUJD",
        "a quantum padded to two characters": "QUJDRQ==",
        "a quantum padded to three characters": "QUJDREU=",
        "a line break between quanta": "QUJD\nREVG",
        "a line break anywhere in the data": "QU\nJDRE\nVG",
        "blanks in the data": " QU JD\tREVG ",
        // RFC 7468 Figure 1 'base64finl': https://www.rfc-editor.org/rfc/rfc7468#section-3
        "a pad split across a line ending": "QUJDCg=\n=",
      };

      const rejected = {
        "a lone character": "A",
        "two characters with no pad": "AA",
        "three characters with no pad": "AAA",
        "a character and a pad": "A=",
        "three characters and two pads": "AAA==",
        "a whole quantum and a pad": "AAAA=",
        "a quantum and one character": "AAAAA",
        "a whole quantum and two pads": "AAAA==",
        "a pad in the middle of the data": "QUJD=REVG",
        "a character outside the base64 alphabet": "QU-JD",
        "nothing at all": "",
        "only blanks": "    ",
        "only padding": "==",
        "a padded line with more data after it": "QUJDCg==\nQUJD",
      };

      Object.entries(accepted).forEach(([description, data]) => {
        it(`accepts ${description} either way, and reads the same data`, function () {
          expect(utils.toPem(wrap(data))).to.equal(utils.toPem(data, "PKCS7"));
        });
      });

      Object.entries(rejected).forEach(([description, data]) => {
        it(`rejects ${description} either way, for the same reason`, function () {
          expect(() => utils.toPem(wrap(data), "PKCS7")).to.throw("Invalid PEM format.");
          expect(() => utils.toPem(data, "PKCS7")).to.throw("Invalid PEM format.");
        });
      });
    });

    describe("accepts what common tooling produces", function () {
      const normalizedPem = fs.readFileSync("./test/static/client_public.pem", "latin1");
      const lines = normalizedPem.trim().split("\n");
      const body = lines.slice(1, -1);
      const rebuild = (bodyLines: string[]) =>
        [lines[0], ...bodyLines, lines[lines.length - 1]].join("\n");

      it("blanks at the ends of lines", function () {
        expect(utils.toPem(rebuild(body.map((line) => `${line}  `)))).to.equal(normalizedPem);
      });

      it("a pretty-printer's indentation", function () {
        expect(utils.toPem(rebuild(body.map((line) => `    ${line}`)))).to.equal(normalizedPem);
      });

      it("a line ending replaced by a space", function () {
        expect(utils.toPem(rebuild([body.join(" ")]))).to.equal(normalizedPem);
      });

      for (const [name, eol] of [
        ["CRLF", "\r\n"],
        ["CR", "\r"],
      ] as const) {
        it(`${name} line endings, with and without boundaries`, function () {
          const bare = body.join("\n").replace(/\n/g, eol);

          expect(utils.toPem(bare, "CERTIFICATE")).to.equal(normalizedPem);
          expect(utils.toPem(rebuild(body).replace(/\n/g, eol))).to.equal(normalizedPem);
        });
      }

      it("a blank line between concatenated messages", function () {
        const pair = `${normalizedPem}\n\n${normalizedPem}`;

        expect(utils.toPem(pair)).to.equal(`${normalizedPem}${normalizedPem}`);
      });

      it("a blank line after the header", function () {
        expect(utils.toPem(rebuild(["", ...body]))).to.equal(normalizedPem);
      });

      it("a blank line in base64 given without boundaries", function () {
        // XMLDSig carries a certificate as xs:base64Binary, whose lexical space collapses
        // whitespace, so a blank line among the lines of an X509Certificate is insignificant.
        // Inside a message the body is RFC 7468's, which has no blank line in it.
        const interrupted = [...body.slice(0, 2), "", ...body.slice(2)].join("\n");

        expect(utils.toPem(interrupted, "CERTIFICATE")).to.equal(normalizedPem);
      });

      it("a line width other than 64", function () {
        const rewrapped = body.join("").match(/.{1,70}/g) ?? [];

        expect(utils.toPem(rebuild(rewrapped))).to.equal(normalizedPem);
      });

      it("nonzero pad bits, written back as zeros", function () {
        // `w` and `x` differ only in bits past the last octet, so both decode alike, but only the
        // zeros are in xs:base64Binary's lexical space.
        const feide = fs.readFileSync("./test/static/feide_public.pem", "latin1");

        expect(utils.toPem(feide.replace("4PF13w==", "4PF13x=="))).to.equal(feide);
      });

      it("a UTF-8 BOM, as decoded text", function () {
        expect(utils.toPem(`\uFEFF${normalizedPem}`)).to.equal(normalizedPem);
      });

      it("a UTF-8 BOM, as the bytes a latin1 read gives", function () {
        const withBom = Buffer.concat([
          Buffer.from([0xef, 0xbb, 0xbf]),
          Buffer.from(normalizedPem, "latin1"),
        ]);

        expect(utils.toPem(withBom.toString("latin1"))).to.equal(normalizedPem);
      });

      it("a Buffer holding the bytes of a PEM file, rather than DER", function () {
        expect(utils.toPem(fs.readFileSync("./test/static/client_public.pem"))).to.equal(
          normalizedPem,
        );
      });

      for (const [name, prefix] of [
        ["a UTF-8 BOM", Buffer.from([0xef, 0xbb, 0xbf])],
        ["blank lines", Buffer.from("\r\n  \n")],
      ] as const) {
        it(`a Buffer holding a PEM file that opens with ${name}, rather than DER`, function () {
          const file = Buffer.concat([prefix, fs.readFileSync("./test/static/client_public.pem")]);

          expect(utils.toPem(file)).to.equal(normalizedPem);
        });
      }

      for (const [name, value, label] of [
        ["blank lines around a message", `\n\n${normalizedPem}\n\n`, undefined],
        ["a line ending after bare base64", `${body.join("\n")}\n`, "CERTIFICATE"],
        [
          "blanks and CRLF around bare base64",
          `\r\n  \r\n${body.join("\r\n")}\r\n\t\r\n`,
          "CERTIFICATE",
        ],
      ] as const) {
        it(name, function () {
          expect(utils.toPem(value, label)).to.equal(normalizedPem);
        });
      }

      it("several certificates in one value", function () {
        const bundle = fs.readFileSync("./test/static/client_bundle.pem", "latin1");

        expect(utils.toPem(bundle).match(/-----BEGIN CERTIFICATE-----/g)).to.have.lengthOf(2);
      });

      it("and hands OpenSSL something it can load", function () {
        // Blanks after an encapsulation boundary are the 'preeb *WSP eol' of RFC 7468 Figure 1,
        // and OpenSSL will not read a certificate that carries them.
        const untidy = rebuild(body)
          .split("\n")
          .map((line) => `${line}  `)
          .join("\r\n");

        expect(() => crypto.createPublicKey(utils.toPem(untidy))).to.not.throw();
      });
    });

    describe("labels", function () {
      const data = fs
        .readFileSync("./test/static/client_public.pem", "latin1")
        .trim()
        .split("\n")
        .slice(1, -1)
        .join("");

      for (const label of ["CERTIFICATE", "PUBLIC KEY", "X509 CRL", "ENCRYPTED PRIVATE KEY"]) {
        it(`wraps base64 in a message labelled "${label}"`, function () {
          const pem = utils.toPem(data, label);

          expect(pem).to.contain(`-----BEGIN ${label}-----\n`);
          expect(pem).to.contain(`-----END ${label}-----\n`);
          // A label this parser writes is one it reads back, or the value is good for one trip.
          expect(utils.toPem(pem)).to.equal(pem);
        });
      }

      it("keeps a hyphen inside a label, which RFC 7468 allows", function () {
        expect(utils.toPem(utils.toPem(data, "FOO-BAR"))).to.contain("-----BEGIN FOO-BAR-----");
      });

      it("writes the longest label it takes on one line, and reads it back", function () {
        // `-----BEGIN ` and `-----` bracket the label in 16 characters, so 48 is the longest one
        // whose opening boundary still fits a 64-character line.
        const longest = "A".repeat(48);
        const pem = utils.toPem(data, longest);

        expect(`-----BEGIN ${longest}-----`).to.have.lengthOf(64);
        expect(pem).to.contain(`-----BEGIN ${longest}-----\n`);
        expect(pem).to.contain(`-----END ${longest}-----\n`);
        expect(utils.toPem(pem)).to.equal(pem);
      });

      it("refuses a label too long for a boundary to carry on one line", function () {
        // The separators of RFC 7468's 'label' count toward the length as its label characters
        // do: 25 label characters with a space between each pair is 49, one over.
        const tooLong = Array(25).fill("A").join(" ");

        expect(tooLong).to.have.lengthOf(49);
        expect(() => utils.toPem(data, tooLong)).to.throw("Invalid PEM label.");
        expect(() =>
          utils.toPem(`-----BEGIN ${tooLong}-----\nQUFBQQ==\n-----END ${tooLong}-----\n`),
        ).to.throw("Invalid PEM format.");
      });

      it("refuses a message labelled nothing, which the grammar marks as 'empty ok'", function () {
        // A message labelled nothing names no format, and OpenSSL answers it with
        // ERR_OSSL_UNSUPPORTED, so reading one would only move the failure later.
        expect(() => utils.toPem("-----BEGIN -----\nQUFBQQ==\n-----END -----\n")).to.throw(
          "Invalid PEM format.",
        );
      });

      it("refuses a label that would write a boundary into the message", function () {
        expect(() => utils.toPem(data, "A-----BEGIN CERTIFICATE-----B")).to.throw(
          "Invalid PEM label.",
        );
      });

      for (const [problem, label] of [
        ["is empty", ""],
        ["opens with a blank", " CERTIFICATE"],
        ["closes with a blank", "CERTIFICATE "],
        ["holds a line break", "CERT\nIFICATE"],
      ] as const) {
        it(`refuses a label that ${problem}`, function () {
          expect(() => utils.toPem(data, label)).to.throw("Invalid PEM label.");
        });
      }
    });

    describe("keys, not only certificates", function () {
      for (const [name, file, label] of [
        ["a private key", "client.pem", "PRIVATE KEY"],
        ["an RSA public key", "saml_external_ns.pem", "RSA PUBLIC KEY"],
      ] as const) {
        it(`normalizes ${name}, from PEM and from bare base64 alike`, function () {
          const pem = fs.readFileSync(`./test/static/${file}`, "latin1");
          const normalized = `${pem.trim()}\n`;
          const data = pem.trim().split("\n").slice(1, -1).join("");

          expect(utils.toPem(pem)).to.equal(normalized);
          expect(utils.toPem(data, label)).to.equal(normalized);
          expect(utils.toPem(data.match(/.{1,32}/g)?.join("\n") ?? "", label)).to.equal(normalized);
        });
      }

      it("round-trips a public key OpenSSL exports, which holds no certificate", function () {
        const privateKey = fs.readFileSync("./test/static/client.pem", "latin1");
        const spki = crypto.createPublicKey(privateKey).export({ type: "spki", format: "pem" });

        expect(utils.toPem(spki.toString())).to.equal(spki);
        expect(utils.pemCertificates(spki.toString())).to.be.empty;
      });
    });

    describe("a traditional encrypted key", function () {
      // Node exports a PKCS#1 key encrypted the traditional way, with `Proc-Type` and `DEK-Info`
      // header fields naming the cipher before the data they make readable.
      const encrypted = crypto
        .createPrivateKey(fs.readFileSync("./test/static/client.pem"))
        .export({ type: "pkcs1", format: "pem", cipher: "aes-256-cbc", passphrase: "secret" })
        .toString();

      it("is neither rewritten nor decoded, since its data is lost without its fields", function () {
        expect(encrypted).to.contain("DEK-Info: AES-256-CBC,");
        expect(() => utils.toPem(encrypted)).to.throw("Invalid PEM format.");
        expect(() => utils.pemToDer(encrypted)).to.throw("Invalid PEM format.");
      });
    });

    describe("rejects data that is not base64", function () {
      const normalizedPem = fs.readFileSync("./test/static/client_public.pem", "latin1");
      const lines = normalizedPem.trim().split("\n");
      const corrupt = (body: string) => [lines[0], body, lines[lines.length - 1]].join("\n");

      it("a body that is not base64 at all", function () {
        expect(() => utils.toPem(corrupt("not base64 at all!"))).to.throw("Invalid PEM format.");
      });

      it("a body that is one long run of blanks", function () {
        expect(() => utils.toPem(corrupt(" ".repeat(80000)))).to.throw("Invalid PEM format.");
      });

      it("a body with a blank line in the middle of the data", function () {
        const body = lines.slice(1, -1);
        const interrupted = [...body.slice(0, 2), "", ...body.slice(2)].join("\n");

        expect(() => utils.toPem(corrupt(interrupted))).to.throw("Invalid PEM format.");
      });

      it("two messages sharing one line", function () {
        // Nothing stands between the footer and the next header, so the two boundaries fall on
        // one line and neither is a line of its own. Refused rather than read as one message,
        // which would return a value with the second certificate quietly missing.
        const run = `${normalizedPem.trim()}${normalizedPem.trim()}`;

        expect(() => utils.toPem(run)).to.throw("Invalid PEM format.");
      });

      it("a message whose two labels disagree", function () {
        const mismatched = normalizedPem.replace("-----END CERTIFICATE-----", "-----END KEY-----");

        expect(() => utils.toPem(mismatched)).to.throw("Invalid PEM format.");
      });

      for (const [name, value] of [
        ["an empty string", ""],
        ["an empty Buffer", Buffer.alloc(0)],
        ["blanks and nothing else", "   \n\t  "],
      ] as const) {
        it(name, function () {
          expect(() => utils.toPem(value, "CERTIFICATE")).to.throw("Invalid PEM format.");
        });
      }

      it("a body whose final quantum is incomplete", function () {
        expect(() => utils.toPem(corrupt(`${lines.slice(1, -1).join("\n")}A`))).to.throw(
          "Invalid PEM format.",
        );
      });
    });

    describe("rejects a value it cannot account for whole", function () {
      const normalizedPem = fs.readFileSync("./test/static/client_public.pem", "latin1");
      const lines = normalizedPem.trim().split("\n");
      const header = lines[0];
      const footer = lines[lines.length - 1];
      const body = lines.slice(1, -1);
      const last = body.length - 1;

      for (const [place, value] of [
        ["the header's line", [`${header}${body[0]}`, ...body.slice(1), footer].join("\n")],
        [
          "the footer's line",
          [header, ...body.slice(0, last), `${body[last]}${footer}`].join("\n"),
        ],
        ["both boundaries' line", `${header}${body.join("")}${footer}`],
      ] as const) {
        it(`data on ${place}`, function () {
          expect(() => utils.toPem(value)).to.throw("Invalid PEM format.");
        });
      }

      it("a message that is opened and never closed", function () {
        // A ReDoS regression in node-saml. What is asserted is the rejection, since a timer would
        // measure the runner rather than the pattern.
        const unclosed = `-----BEGIN CERTIFICATE-----\r\n${"AAAA\r\n".repeat(26)}!`;

        expect(() => utils.toPem(unclosed)).to.throw("Invalid PEM format.");
      });

      it("a header followed directly by its footer", function () {
        expect(() => utils.toPem(`${header}\n${footer}\n`)).to.throw("Invalid PEM format.");
      });

      for (const [place, value] of [
        ["before the message", `subject=/CN=client\n${normalizedPem}`],
        ["after the message", `${normalizedPem}Issued for testing.\n`],
        ["between two messages", `${normalizedPem}and its issuer:\n${normalizedPem}`],
      ] as const) {
        it(`explanatory text ${place}`, function () {
          expect(() => utils.toPem(value)).to.throw("Invalid PEM format.");
        });
      }
    });
  });

  describe("pemToDer", function () {
    it("will return a Buffer of binary DER when given a normalized PEM format", function () {
      const pem = fs.readFileSync("./test/static/client_public.pem", "latin1");
      const derBuffer = fs.readFileSync("./test/static/client_public.der");

      const result = utils.pemToDer(pem);
      expect(result).to.be.instanceOf(Buffer);
      expect(result).to.deep.equal(derBuffer);
    });

    it("will throw if the format is not PEM", function () {
      expect(() => utils.pemToDer("not a pem")).to.throw();
    });

    it("returns the bytes of a message of any label, which OpenSSL loads back", function () {
      const key = utils.pemToDer(fs.readFileSync("./test/static/client.pem", "latin1"));

      expect(() => crypto.createPrivateKey({ key, format: "der", type: "pkcs8" })).to.not.throw();
    });

    it("will throw if the encapsulated data is not base64", function () {
      const pem = fs.readFileSync("./test/static/client_public.pem", "latin1").trim().split("\n");
      const corrupt = [pem[0], "not base64 at all!", pem[pem.length - 1]].join("\n");

      expect(() => utils.pemToDer(corrupt)).to.throw("Invalid PEM format.");
    });

    it("will throw if the value holds more than one PEM message", function () {
      const bundle = fs.readFileSync("./test/static/client_bundle.pem", "latin1");

      expect(() => utils.pemToDer(bundle)).to.throw("Expected a single PEM message, but found 3.");
    });

    it("will throw, not return the first, when later boundaries run together", function () {
      // A footer and the next header on one line are not two messages, so counting the messages
      // alone would find one and hand back its bytes with the rest of the value discarded.
      const runTogether = fs
        .readFileSync("./test/static/client_bundle.pem", "latin1")
        .replace("-----\n-----BEGIN ", "----------BEGIN ");

      expect(runTogether).to.contain("----------BEGIN ");
      expect(() => utils.pemToDer(runTogether)).to.throw("Invalid PEM format.");
    });
  });

  describe("reads a CERTIFICATE message's data as X.509, and not only as base64", function () {
    // The base64 rules above hold for every label. Under CERTIFICATE the data is handed to Node's
    // X509Certificate as well, so data those rules accept is still refused if it is no certificate.
    const certificate = fs.readFileSync("./test/static/client_public.der");
    const wrap = (der: Buffer) =>
      `-----BEGIN CERTIFICATE-----\n${der.toString("base64")}\n-----END CERTIFICATE-----\n`;

    const moreAfter = "Expected a single certificate, but found more data after it.";

    // The fixture's outer length is `82 01C4`. Written `83 0001C4` it is the same length in a
    // longer form, and written `80` with two zero octets after the contents it is indefinite: both
    // are BER and not DER, which RFC 7468 section 5.1 and XML Signature 1.1 both allow.
    const longForm = Buffer.concat([Buffer.from([0x30, 0x83, 0x00]), certificate.subarray(2)]);
    const indefinite = Buffer.concat([
      Buffer.from([0x30, 0x80]),
      certificate.subarray(4),
      Buffer.from([0, 0]),
    ]);

    for (const [encoding, der] of [
      ["DER", certificate],
      ["BER with a long-form length", longForm],
      ["BER with an indefinite length", indefinite],
    ] as const) {
      it(`accepts a certificate encoded as ${encoding}, and keeps its octets as given`, function () {
        // XML Signature 1.1 says an implementation SHOULD NOT alter or re-encode a certificate.
        expect(utils.pemToDer(utils.toPem(wrap(der)))).to.deep.equal(der);
        expect(utils.pemToDer(utils.toPem(der, "CERTIFICATE"))).to.deep.equal(der);
        expect(utils.pemToDer(wrap(der))).to.deep.equal(der);
        expect(utils.pemCertificates(wrap(der))).to.deep.equal([der.toString("base64")]);
      });
    }

    for (const [problem, der, error] of [
      [
        "well-formed base64 that is no certificate",
        Buffer.from("base64, and no certificate"),
        "Invalid PEM format.",
      ],
      ["a certificate cut short", certificate.subarray(0, -1), "Invalid PEM format."],
      // X509Certificate reads the first certificate in the bytes and ignores what follows, which
      // 6.x passed on for Node to do the same, so these are refused with a reason of their own.
      [
        "a certificate with a second run into it",
        Buffer.concat([certificate, certificate]),
        moreAfter,
      ],
      [
        "a certificate with other bytes after it",
        Buffer.concat([certificate, Buffer.from("more")]),
        moreAfter,
      ],
      [
        "a BER certificate with bytes after it",
        Buffer.concat([longForm, Buffer.from("more")]),
        moreAfter,
      ],
      [
        "an indefinite-length certificate with bytes after it",
        Buffer.concat([indefinite, certificate]),
        moreAfter,
      ],
    ] as const) {
      it(`refuses ${problem}, in each function that reads one`, function () {
        expect(() => utils.toPem(wrap(der))).to.throw(error);
        expect(() => utils.toPem(der.toString("base64"), "CERTIFICATE")).to.throw(error);
        expect(() => utils.toPem(der, "CERTIFICATE")).to.throw(error);
        expect(() => utils.pemToDer(wrap(der))).to.throw(error);
        expect(() => utils.pemCertificates(wrap(der))).to.throw(error);
      });
    }

    it("and holds the data of any other label to the base64 rules alone", function () {
      const data = Buffer.from("base64, and no certificate");
      const pem = `-----BEGIN PKCS7-----\n${data.toString("base64")}\n-----END PKCS7-----\n`;

      expect(utils.pemToDer(pem)).to.deep.equal(data);
    });
  });

  describe("pemCertificates", function () {
    const bundle = fs.readFileSync("./test/static/client_bundle.pem", "latin1");

    it("returns the base64 of every certificate, and only certificates", function () {
      const certificates = utils.pemCertificates(bundle);

      // The bundle carries a private key alongside its two certificates, and publishing that in
      // KeyInfo would hand out the signing key: https://www.w3.org/TR/xmldsig-core1/#sec-X509Data
      expect(certificates).to.have.lengthOf(2);
      for (const certificate of certificates) {
        expect(certificate).to.match(/^[A-Za-z0-9+/]+={0,2}$/);
        expect(() =>
          crypto.createPublicKey(utils.toPem(certificate, "CERTIFICATE")),
        ).to.not.throw();
      }
    });

    describe("passes over the explanatory text around a message", function () {
      // RFC 7468 section 5.2 shows a certificate written under its subject and issuer lines, and
      // both OpenSSL and keytool put them there, so a value carrying them is still a value
      // carrying a certificate. Section 2 allows the data before an encapsulation boundary.
      const certificate = fs.readFileSync("./test/static/client_public.pem", "latin1");
      const data = certificate.trim().split("\n").slice(1, -1).join("");

      it("before the message", function () {
        const value = `subject=/CN=client\nissuer=/CN=ca\n${certificate}`;

        expect(utils.pemCertificates(value)).to.deep.equal([data]);
      });

      it("after the message", function () {
        expect(utils.pemCertificates(`${certificate}Issued for testing.\n`)).to.deep.equal([data]);
      });

      it("between two messages", function () {
        const value = `${certificate}and its issuer:\n\n${certificate}`;

        expect(utils.pemCertificates(value)).to.deep.equal([data, data]);
      });

      it("but not an opening boundary no message was built from", function () {
        const value = `${certificate}and one more:\n-----BEGIN CERTIFICATE-----\n`;

        expect(() => utils.pemCertificates(value)).to.throw("Invalid PEM format.");
      });

      for (const [place, value] of [
        ["before the header", `prefix${certificate}`],
        // A line opening with `-----` is held to be a boundary and keeps its blanks, so this is
        // the shape that reaches the header with text still in front of it.
        ["before the header, itself opening with dashes", `-----X${certificate}`],
        ["after the footer", `${certificate.trim()}suffix\n`],
      ] as const) {
        it(`and not text sharing a boundary's line, ${place}`, function () {
          // Figure 1 gives an encapsulation boundary a line of its own, so text on that line is
          // not the explanatory text around a message and is not passed over as though it were.
          expect(() => utils.pemCertificates(value)).to.throw("Invalid PEM format.");
        });
      }
    });

    it("reads certificates out of a bundle that also holds a traditional encrypted key", function () {
      const encrypted = crypto
        .createPrivateKey(fs.readFileSync("./test/static/client.pem"))
        .export({ type: "pkcs1", format: "pem", cipher: "aes-256-cbc", passphrase: "secret" })
        .toString();
      const certificate = fs.readFileSync("./test/static/client_public.pem", "latin1");

      expect(utils.pemCertificates(`${certificate}${encrypted}`)).to.deep.equal([
        certificate.trim().split("\n").slice(1, -1).join(""),
      ]);
    });

    it("refuses a certificate with header fields, which only an encrypted key carries", function () {
      const certificate = fs.readFileSync("./test/static/client_public.pem", "latin1");
      const withFields = certificate.replace(
        "-----\n",
        "-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00\n\n",
      );

      expect(() => utils.pemCertificates(withFields)).to.throw("Invalid PEM format.");
    });

    it("returns base64 with its pad bits zeroed", function () {
      const feide = fs.readFileSync("./test/static/feide_public.pem", "latin1");

      expect(utils.pemCertificates(feide.replace("4PF13w==", "4PF13x=="))).to.deep.equal([
        feide.trim().split("\n").slice(1, -1).join(""),
      ]);
    });

    it("returns an empty array when the value holds no message at all", function () {
      const data = bundle.split("\n").slice(1, 19).join("");

      expect(utils.pemCertificates("")).to.deep.equal([]);
      expect(utils.pemCertificates(data)).to.deep.equal([]);
    });

    it("throws when the value opens a message it does not close", function () {
      // Dropping one footer leaves the next header where data should be, which is a different
      // malformation from a message left open at the end, so both are worth their own case.
      const interleaved = bundle.replace(/-----END CERTIFICATE-----/, "");
      const unclosed = `${bundle}\n-----BEGIN CERTIFICATE-----\nQUFBQQ==\n`;
      const empty = `${bundle}\n-----BEGIN CERTIFICATE-----\n`;

      for (const value of [interleaved, unclosed, empty]) {
        expect(() => utils.pemCertificates(value)).to.throw("Invalid PEM format.");
      }
    });

    it("throws when a message's labels disagree, whichever of them is a certificate", function () {
      const pem = fs.readFileSync("./test/static/client_public.pem", "latin1");

      // The opening label alone decides what a message is, so a message that opens as something
      // else is not a certificate to filter away: it is a certificate that failed to parse.
      expect(() =>
        utils.pemCertificates(pem.replace("BEGIN CERTIFICATE", "BEGIN PRIVATE KEY")),
      ).to.throw("Invalid PEM format.");
      expect(() =>
        utils.pemCertificates(pem.replace("END CERTIFICATE", "END PRIVATE KEY")),
      ).to.throw("Invalid PEM format.");
    });

    it("throws when a certificate's data is not base64", function () {
      const corrupt = bundle.replace(/^[A-Za-z0-9+/]{64}$/m, "not base64 at all!");

      expect(() => utils.pemCertificates(corrupt)).to.throw("Invalid PEM format.");
    });
  });
});
