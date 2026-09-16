import { analyzeFile } from "@/lib/scanner";

const ID = "license-header-contamination";

function findings(content: string, path = "src/example.ts") {
  const result = analyzeFile(path, content);
  return result.indicators.filter(i => i.id === ID);
}

describe("license contamination -- SPDX identifiers", () => {
  it("flags an SPDX GPL identifier", () => {
    const content = `
// SPDX-License-Identifier: GPL-3.0-only
function processPayment(amount) {
  return amount * 1.05;
}
`;
    const hits = findings(content);
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe("medium");
    expect(hits[0].detail).toContain("General Public License");
  });

  it("flags an SPDX MIT identifier and reports the real line number", () => {
    const content = `
function alpha() {}
function beta() {}
// SPDX-License-Identifier: MIT
function processOrder(order) {
  return order.total;
}
`;
    const hits = findings(content);
    expect(hits.some(h => h.line === 4)).toBe(true);
  });
});

describe("license contamination -- full license header boilerplate", () => {
  it("flags a verbatim GPL preamble", () => {
    const content = `
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

function computeInterest(principal, rate) {
  return principal * rate;
}
`;
    const hits = findings(content);
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].detail).toContain("General Public License");
  });

  it("flags a verbatim AGPL preamble and distinguishes it from plain GPL", () => {
    const content = `
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation.

function syncData(records) {
  return records.map(r => r.id);
}
`;
    const hits = findings(content);
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].detail).toContain("Affero");
  });

  it("flags a verbatim Apache 2.0 header", () => {
    const content = `
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

func computeChecksum(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}
`;
    const hits = findings(content, "internal/checksum.go");
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].detail).toContain("Apache");
  });

  it("flags a verbatim MIT header", () => {
    const content = `
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction.

def normalize_path(path):
    return path.strip("/")
`;
    const hits = findings(content, "utils/paths.py");
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].detail).toContain("MIT");
  });

  it("flags a verbatim BSD header", () => {
    const content = `
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met.

func Reverse(s string) string {
	return s
}
`;
    const hits = findings(content, "internal/strutil.go");
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].detail).toContain("BSD");
  });
});

describe("license contamination -- third-party copyright notices", () => {
  it("flags a Copyright (c) notice naming a third party", () => {
    const content = `
// Copyright (c) 2015 Example Systems, Inc. All rights reserved.

function parseManifest(raw) {
  return JSON.parse(raw);
}
`;
    const hits = findings(content);
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].detail).toContain("copyright notice");
    expect(hits[0].confidence).toBeLessThan(60); // lower-confidence tier than SPDX/boilerplate
  });
});

describe("license contamination -- language-agnostic (Python/Go fixtures above already cover this) and true negatives", () => {
  it("does not flag a comment merely mentioning a license by name without verbatim boilerplate", () => {
    const content = `
function run() {
  // Note: this approach is inspired by an MIT-licensed library we evaluated
  return doWork();
}
`;
    expect(findings(content)).toHaveLength(0);
  });

  it("does not flag license text inside a fix-suggestion example/snippet field", () => {
    const content = `
const fixSuggestion = {
  id: "some-check",
  example: "SPDX-License-Identifier: GPL-3.0-only",
  code_before: "SPDX-License-Identifier: MIT",
};
`;
    expect(findings(content)).toHaveLength(0);
  });

  it("does not escalate risk_score for a hit inside a vendored/minified file", () => {
    const filler = "x".repeat(420);
    const content = `${filler}; // SPDX-License-Identifier: GPL-3.0-only`;
    const result = analyzeFile("vendor/lib.min.js", content);
    const hit = result.indicators.find(i => i.id === ID);
    expect(hit?.codeCategory).toBe("third_party");
  });
});
