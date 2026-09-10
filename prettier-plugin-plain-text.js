// Prettier only enforces `endOfLine` on files it can parse. This parser prints its input back
// unchanged, so the files listed here get the line-ending check and nothing else.
module.exports = {
  languages: [
    {
      name: "Plain text",
      parsers: ["plain-text"],
      extensions: [".pem"],
      filenames: [
        ".eslintignore",
        ".gitattributes",
        ".gitignore",
        ".npmignore",
        ".prettierignore",
        "LICENSE",
        "package-lock.json",
      ],
    },
  ],
  parsers: {
    "plain-text": {
      astFormat: "plain-text",
      parse: (text) => ({ text }),
      locStart: () => 0,
      locEnd: (node) => node.text.length,
    },
  },
  printers: {
    "plain-text": { print: (path) => path.node.text },
  },
};
