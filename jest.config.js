/** @type {import('jest').Config} */
const config = {
  testEnvironment: "jsdom",
  transform: {
    "^.+\\.(ts|tsx)$": ["ts-jest", {
      tsconfig: { jsx: "react-jsx" },
    }],
    // java-parser (Phase 3 Java AST taint engine, astTaintJava.ts) and its
    // whole dependency chain -- chevrotain, chevrotain-allstar, every
    // @chevrotain/* sub-package, lodash-es -- ship ESM-only with no CJS
    // build at all (confirmed directly: none of their package.json exports
    // maps have a "require" condition). Jest's default CJS module loader
    // can't require() raw `import` syntax, so these need babel's ESM->CJS
    // transform. Everything else in node_modules stays untransformed via
    // the transformIgnorePatterns override below.
    // [\\/] (not a literal /) since transformIgnorePatterns/transform keys
    // are matched against the raw absolute path, backslashes and all, on
    // Windows -- a literal "/"-only pattern silently never matches there.
    "node_modules[\\\\/](java-parser|chevrotain|chevrotain-allstar|@chevrotain|lodash-es)[\\\\/].+\\.js$": ["babel-jest", {
      configFile: "./babel.config.jest.js",
    }],
  },
  transformIgnorePatterns: [
    "node_modules[\\\\/](?!(java-parser|chevrotain|chevrotain-allstar|@chevrotain|lodash-es)[\\\\/])",
  ],
  moduleNameMapper: {
    "^@/(.*)$": "<rootDir>/src/$1",
    "\\.(css|less|scss|svg|png|jpg|gif)$": "<rootDir>/src/__tests__/__mocks__/fileMock.js",
    // lodash-es is a straight ESM re-export of plain lodash (identical API) --
    // redirecting to the real CJS "lodash" sidesteps needing to transform it
    // (and its many lodash-es/<fn>.js deep-subpath imports) at all.
    "^lodash-es$": "lodash",
    "^lodash-es/(.*)$": "lodash/$1",
    // The rest of java-parser's dependency chain (chevrotain and its
    // @chevrotain/* sub-packages) ship package.json "exports" maps with only
    // an "import" condition and no "require"/"default" fallback -- Jest's
    // CJS-context resolver can't match those at all, even after babel
    // converts the calling code's `import` to `require()`. Map each bare
    // specifier directly to its real ESM entry file instead, bypassing
    // exports-conditions matching entirely; the resolved path still lives
    // under node_modules/<pkg>/..., so the babel-jest transform rule above
    // still applies to it via path matching.
    "^chevrotain$": "<rootDir>/node_modules/chevrotain/lib/src/api.js",
    "^@chevrotain/gast$": "<rootDir>/node_modules/@chevrotain/gast/lib/src/api.js",
    "^@chevrotain/cst-dts-gen$": "<rootDir>/node_modules/@chevrotain/cst-dts-gen/lib/src/api.js",
    "^@chevrotain/utils$": "<rootDir>/node_modules/@chevrotain/utils/lib/src/api.js",
    "^@chevrotain/regexp-to-ast$": "<rootDir>/node_modules/@chevrotain/regexp-to-ast/lib/src/api.js",
  },
  setupFilesAfterEnv: ["<rootDir>/src/__tests__/setup.ts"],
  testMatch: ["**/__tests__/**/*.test.(ts|tsx)"],
  collectCoverageFrom: [
    "src/lib/**/*.ts",
    "src/components/**/*.tsx",
    "src/app/**/*.tsx",
    "!src/**/*.d.ts",
    "!src/**/__mocks__/**",
  ],
  coverageReporters: ["text", "lcov"],
};

module.exports = config;
