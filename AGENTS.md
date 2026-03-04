# Agent Notes

## Scope

- This repository is a Node.js/TypeScript library.
- Only work in `src/` and `test/` unless explicitly asked to do otherwise.
- Treat all changes as security-sensitive; this library is foundational for other security-focused projects (e.g., `node-saml`).

## Conventions

- Keep changes minimal and focused.
- Prefer defensive coding and preserve existing security properties.
- Follow existing project style and lint rules.
- Don't edit `node_modules/`.

## Verification

- After all changes, run:
  - `npm run build && npm test && npm run lint:fix`
