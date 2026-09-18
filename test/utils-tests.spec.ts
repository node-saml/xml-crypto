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
      const wrap = (data: string) =>
        `-----BEGIN CERTIFICATE-----\n${data}\n-----END CERTIFICATE-----`;

      const accepted = {
        "a whole quantum": "QUJD",
        "a quantum padded to two characters": "QUJDRQ==",
        "a quantum padded to three characters": "QUJDREU=",
        "a line break between quanta": "QUJD\nREVG",
        "a line break anywhere in the data": "QU\nJDRE\nVG",
        "blanks in the data": " QU JD\tREVG ",
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
      };

      Object.entries(accepted).forEach(([description, data]) => {
        it(`accepts ${description} either way, and reads the same certificate`, function () {
          expect(utils.toPem(wrap(data))).to.equal(utils.toPem(data, "CERTIFICATE"));
        });
      });

      Object.entries(rejected).forEach(([description, data]) => {
        it(`rejects ${description} either way, for the same reason`, function () {
          expect(() => utils.toPem(wrap(data), "CERTIFICATE")).to.throw("Invalid PEM format.");
          expect(() => utils.toPem(data, "CERTIFICATE")).to.throw("Invalid PEM format.");
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

      it("a line width other than 64", function () {
        const rewrapped = body.join("").match(/.{1,70}/g) ?? [];

        expect(utils.toPem(rebuild(rewrapped))).to.equal(normalizedPem);
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
