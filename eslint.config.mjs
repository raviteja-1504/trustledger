// ESLint 9 flat config (replaces .eslintrc.json; `next lint` was removed in Next 16 -- `npm run lint` runs eslint).
import nextCoreWebVitals from "eslint-config-next/core-web-vitals";

const config = [
  {
    ignores: [
      ".next/**", "node_modules/**", "coverage/**", "playwright-report/**", "test-results/**",
      "public/**", "next-env.d.ts", "*.tsbuildinfo",
    ],
  },
  ...nextCoreWebVitals,
  {
    // Same files Next's configs register their plugins for (scripts/*.cjs are not linted).
    files: ["**/*.{js,jsx,mjs,ts,tsx,mts,cts}"],
    rules: {
      "react/no-unescaped-entities": "off",
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": "off",
      "@typescript-eslint/no-require-imports": "off",
      "@typescript-eslint/no-var-requires": "off",
      "react-hooks/exhaustive-deps": "warn",
      "@next/next/no-img-element": "warn",
      // New in eslint-plugin-react-hooks v7 (Next 16): React Compiler rules. They flag patterns that work today
      // (e.g. setState inside an effect) across ~50 files; kept visible as warnings and fixed separately rather
      // than rewritten in bulk as part of the framework upgrade.
      "react-hooks/set-state-in-effect": "warn",
      "react-hooks/purity": "warn",
      "react-hooks/refs": "warn",
      "react-hooks/preserve-manual-memoization": "warn",
      "react-hooks/use-memo": "warn",
      "react-hooks/globals": "warn",
      "react-hooks/immutability": "warn",
    },
  },
  // ESLint 9 reports unused eslint-disable comments by default; ESLint 8 (before Next 16) didn't.
  { linterOptions: { reportUnusedDisableDirectives: "off" } },
];

export default config;
