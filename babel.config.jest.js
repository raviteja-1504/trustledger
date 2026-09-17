// Used ONLY by jest.config.js's babel-jest transform, scoped to java-parser's
// ESM-only dependency chain (see the comment there for why this exists).
// Not used anywhere else -- the app itself builds via Next's own SWC/webpack
// pipeline, and every other test file is handled by ts-jest, not babel.
module.exports = {
  presets: [["@babel/preset-env", { targets: { node: "current" } }]],
};
