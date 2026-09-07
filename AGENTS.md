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

The suite is not here to cover the code. It exists to catch two specific failures, and a
test that is not chasing one of them probably should not exist.

Every test has the same shape. Give the library:

- **XML** — a document crafted to exercise the case.
- **A configuration a JavaScript caller could actually pass.** The types only protect
  TypeScript users. If a configuration is reachable from plain JavaScript then it is
  reachable in production, whether or not `tsc` would have rejected it, so write the test
  for what JavaScript allows rather than for what the types permit. When the point of the
  test is that a JavaScript caller can reach that state, casting away the type error is
  correct; use `as`, since `!` assertions fail lint.

Then assert that the library does neither of these:

1. **Returns improper data.** Output that violates the specs, fails to interoperate with
   documents other implementations produce, or ignores an established best practice.
2. **Claims something is secure or trusted when it is not.** Reports a signature as
   valid, or data as trustworthy, when the document does not justify it. This is the
   attack-vector case, and the worse of the two, because the caller has no way to detect
   the lie.

Nothing else is likely to earn a test. Don't pin internal implementation details: a test
asserting how a private method behaves, or one that restates the code, catches nothing
and makes refactoring expensive. Add a test when a change alters what the library
accepts, rejects, or emits; skip it when the change is internal and the observable
behavior is identical.

For a bug fix, watch the test fail first. A regression test nobody observed failing — for
the reported reason, not an unrelated one — proves nothing about the fix. A branch that
only reproduces a bug is legitimately red; say so rather than skipping the test to get
green.

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
were done the obvious way, and which non-obvious constraint is being satisfied. Link the
issue or spec that prompted the code.

If a comment is needed at all, keep it DRY. The `it()` name plus a spec link is often the
whole comment. Cite, don't quote: prefer a section number and a URL over the sentence they
contain. Keep it to a line or two.

A comment reading "loop over the references" above a loop over references, or one
restating a field's name as a sentence, earns nothing and costs a review every time the
code beneath it changes. Delete those rather than update them.

JSDoc on exported API is a separate thing and is welcome: it documents the contract for
consumers and surfaces in their editor. Keep it about the contract — parameters, return
values, what throws, what is deprecated — not about the implementation. Reserve the `/** */`
form for that; on internal code and tests it advertises a contract that isn't there.

## Conventions

- Keep changes minimal and focused; use modern semantic coding practices.
- Work in `src/` and `test/` unless asked otherwise.
- Never edit `node_modules/` or `lib/`.
