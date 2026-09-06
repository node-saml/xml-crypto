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

A package's declared `engines` is advisory — npm only warns — so it predicts neither
direction reliably. Some tools declaring a newer Node still run fine on the floor;
others crash on a feature they never declared. Verify by actually running on the oldest
supported version.

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

## Style

- Strict TypeScript (`strict: true`), CommonJS, target ES2020.
- Two lint rules bite often: `deprecation/deprecation` is an error, so calling a
  deprecated API fails lint even when it works; `@typescript-eslint/no-non-null-assertion`
  is an error, so no `!` assertions.
- Prettier owns formatting (`printWidth: 100`). Don't hand-format.
- Prettier 3 does not auto-load plugins. A plugin in `devDependencies` does nothing
  unless it is also listed under `plugins` in `.prettierrc.json`.

## Conventions

- Keep changes minimal and focused; match the surrounding style.
- Work in `src/` and `test/` unless asked otherwise.
- Never edit `node_modules/` or `lib/`.
- Add a test for any behaviour change. The suite is the safety net for a security library.
