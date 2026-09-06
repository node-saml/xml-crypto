# AGENTS.md

## What this is

`xml-crypto` implements XML digital signatures for Node.js. It is published to npm and
depended on by security-sensitive projects such as `node-saml`, so a bug here can become
an authentication bypass downstream. Treat every change as security-relevant.

## Layout

- `src/` — TypeScript source; the only code that ships.
- `src/index.ts` — the public barrel. Anything re-exported here is public API.
- `src/signed-xml.ts` — the core signing and verification logic.
- `test/*.spec.ts` — Mocha specs.
- `test/static/`, `test/validators/` — fixtures. See the warning below.
- `lib/` — build output. Generated; never edit.

## Commands

- `npm run build` — compile `src/` to `lib/`.
- `npm test` — `nyc mocha` over `test/*.spec.ts`.
- `npm run lint` — ESLint plus `prettier --check`.
- `npm run lint:fix` — ESLint `--fix` plus `prettier --write`; rewrites files.

Run `npm run build && npm test && npm run lint` before calling work done.

## Hard constraints

### Fixtures are byte-sensitive

`test/static/` and `test/validators/` contain XML signature fixtures. Canonicalization
and digests depend on the exact bytes, so reformatting whitespace silently invalidates
signatures and the failure can look unrelated. `.prettierignore` excludes both
directories — keep it that way, and never run a formatter over them.

### The supported Node floor is real

`engines` in `package.json` is the contract, and the matrix in
`.github/workflows/ci.yml` runs the suite on every supported version, oldest included.
Read both rather than assuming; they change. Development tooling has to install and run
on the _oldest_ entry, not just the newest.

### The public API is semver-bound

Changing or removing anything re-exported from `src/index.ts`, or altering types in
`src/types.ts`, is breaking for consumers. Changes confined to `devDependencies`,
tests, CI, or tooling are not.

## Security posture

- Verification must fail closed. Never make a check more permissive to get a test green.
- Preserve constant-time comparison where it is used (HMAC verification).
- Be careful with XPath. Expressions can originate from the document under inspection;
  do not broaden what a reference is able to select.
- Prefer an explicit error over silently accepting a malformed document.

## API design

Prefer removing footguns over adding convenience. A default that makes a security
decision on the caller's behalf is a footgun: the caller lives with the consequence
without ever having made the choice.

- Don't add a default for anything security-relevant. Throw instead: the errors
  `signatureAlgorithm is required` and `digestAlgorithm is required` exist so that
  nobody silently inherits SHA-1.
- Where guessing at an extension point would be dangerous, ship an inert default rather
  than a working one. `getCertFromKeyInfo` defaults to `SignedXml.noop`, not to "trust
  the certificate embedded in the document" — that default would let an attacker supply
  the key that verifies their own signature.
- Keep dangerous-but-legitimate features off until asked for. HMAC is supported, but the
  caller has to call `enableHMAC()`.
- A choice is only real if it is documented. When you require the implementer to decide,
  list the sensible options and their trade-offs in `README.md` so they can choose
  knowingly.

## Tests

The suite is not here to cover the code. It is here to pin down the things a signature
library has to get right, which is a much smaller set:

- **Attack vectors** — the ways a crafted document could get a bad signature accepted.
  `describe("Signature self-reference prevention")` in
  `test/signature-object-tests.spec.ts` is the model: it asserts that a `Reference`
  cannot point at `SignedInfo` or at the `Signature` itself.
- **Spec compliance and interoperability** — canonicalization, digests and transforms
  behaving as the specs require, and documents produced by other implementations still
  verifying. That is what the SAML, WS-Fed and Java validator fixtures are for.

Don't test internal implementation details. A test that pins a private method or simply
restates the code catches nothing, and it makes future refactoring expensive. Add a test
when a change alters what the library accepts or rejects; skip it when the change is
internal and the observable behavior is the same.

## Style

- Strict TypeScript (`strict: true`), CommonJS, target ES2020.
- Two lint rules bite often: `deprecation/deprecation` is an error, so calling a
  deprecated API fails lint even when it works; `@typescript-eslint/no-non-null-assertion`
  is an error, so no `!` assertions.
- Prettier owns formatting (`printWidth: 100`). Don't hand-format.

## Comments

Code describes itself. Name things well and keep functions small enough that the _what_
and the _how_ are readable from the code, then don't restate them in prose that goes
stale the first time someone edits the line below it.

Comment only what the code cannot say: _why_ something is done, what would break if it
were done the obvious way, and which non-obvious constraint is being satisfied.
Exceptions, gotchas, threat-model reasoning, spec quirks, and a link to the issue that
prompted the code are all worth writing down.

The constant-time comparison in `src/signature-algorithms.ts` is the model:

```
// Use constant-time comparison to prevent timing attacks (CWE-208)
// See: https://github.com/node-saml/xml-crypto/issues/522

// timingSafeEqual throws if buffer lengths don't match
```

None of that repeats the code. The first two lines say why the comparison has to be
constant-time and where the requirement came from; the third flags behavior of
`timingSafeEqual` that the call site doesn't reveal.

A comment reading "loop over the references" above a loop over references, or one
restating a field's name as a sentence, earns nothing and costs a review every time the
code beneath it changes. Delete those rather than update them.

JSDoc on exported API is a separate thing and is welcome: it documents the contract for
consumers and surfaces in their editor. Keep it about the contract — parameters, return
values, what throws, what is deprecated — not about the implementation.

## Conventions

- Keep changes minimal and focused; use modern semantic coding practices.
- Work in `src/` and `test/` unless asked otherwise.
- Never edit `node_modules/` or `lib/`.
