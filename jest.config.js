/** @type {import('jest').Config} */
const config = {
  testEnvironment: "jsdom",
  transform: {
    "^.+\\.(ts|tsx)$": ["ts-jest", {
      tsconfig: { jsx: "react-jsx" },
    }],
  },
  moduleNameMapper: {
    "^@/(.*)$": "<rootDir>/src/$1",
    "\\.(css|less|scss|svg|png|jpg|gif)$": "<rootDir>/src/__tests__/__mocks__/fileMock.js",
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
