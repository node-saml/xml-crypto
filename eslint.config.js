const js = require("@eslint/js");
const tseslint = require("typescript-eslint");
const globals = require("globals");
const prettierConfig = require("eslint-config-prettier");

module.exports = tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.ts"],
    languageOptions: {
      parserOptions: {
        project: "./tsconfig.eslint.json",
        tsconfigRootDir: __dirname,
        sourceType: "module",
      },
      globals: {
        ...globals.node,
        ...globals.mocha,
        ...globals.es2020,
        Attr: "readonly",
        ChildNode: "readonly",
        Comment: "readonly",
        Document: "readonly",
        Element: "readonly",
        Node: "readonly",
        XPathNSResolver: "readonly",
      },
    },
    rules: {
      "no-console": "error",
      "no-prototype-builtins": "error",
      "one-var": ["error", "never"],
      "no-duplicate-imports": "error",
      "no-use-before-define": "error",
      curly: "error",
      eqeqeq: ["error", "smart"],
      "no-var": "error",
      "prefer-const": "error",
      "prefer-template": "error",
      "@typescript-eslint/no-deprecated": "error",
      "@typescript-eslint/no-non-null-assertion": "error",
      "@typescript-eslint/no-unused-vars": "error",
      "@typescript-eslint/no-this-alias": "error",
    },
  },
  {
    files: ["test/**/*.ts"],
    rules: {
      "@typescript-eslint/no-unused-expressions": "off",
    },
  },
  {
    rules: prettierConfig.rules,
  },
);
