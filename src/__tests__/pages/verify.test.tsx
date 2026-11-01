/**
 * /verify: reads the chosen file in the browser, fetches the published key, and shows the verdict and each step.
 * (The cryptography itself is tested in lib/reportVerification.test.ts.)
 */
import React from "react";
import { act, fireEvent, render, screen, within } from "@testing-library/react";

const verifyEvidence = jest.fn();
jest.mock("@/lib/reportVerification", () => ({ verifyEvidence: (...a: unknown[]) => verifyEvidence(...a) }));

import VerifyClient from "@/app/verify/VerifyClient";

const fileOf = (body: string, name = "r-evidence.json") => Object.assign(new File([body], name), { text: async () => body });
const choose = async (f: File) => {
  await act(async () => { fireEvent.change(screen.getByLabelText("Evidence record"), { target: { files: [f] } }); });
};

let keyStatus = 200;
beforeEach(() => {
  verifyEvidence.mockReset();
  keyStatus = 200;
  global.fetch = jest.fn(async () => ({ ok: keyStatus === 200, status: keyStatus, json: async () => ({ key_id: "abc", public_key_pem: "PEM" }) })) as unknown as typeof fetch;
  Object.defineProperty(globalThis, "crypto", { value: { subtle: {} }, configurable: true });
});

describe("Verify page", () => {
  it("checks the file against the published key and shows each step", async () => {
    verifyEvidence.mockResolvedValue({ verdict: "verified", record_sha256: "e3", report: { id: "R-1", framework: "SOC2", period_start: "2026-10-01T00:00:00Z", period_end: "2026-10-31T00:00:00Z" },
      steps: [{ label: "Signature", ok: true, detail: "Valid: the record is exactly what TrustLedger signed." }] });
    render(<VerifyClient />);
    await choose(fileOf(JSON.stringify({ record: { a: 1 }, signature: {} })));
    expect(global.fetch).toHaveBeenCalledWith("/.well-known/trustledger-export-signing-key");
    expect(verifyEvidence).toHaveBeenCalledWith({ record: { a: 1 }, signature: {} }, { key_id: "abc", public_key_pem: "PEM" }, expect.anything());
    const result = screen.getByRole("region", { name: "Verification result" });
    expect(within(result).getByText("Verified")).toBeInTheDocument();
    expect(result).toHaveTextContent("Report R-1 · SOC2 · 2026-10-01 to 2026-10-31");
    expect(result).toHaveTextContent("Signature: Valid");
  });

  it("no published key is passed on as none (the result then says it can't be verified)", async () => {
    keyStatus = 404;
    verifyEvidence.mockResolvedValue({ verdict: "unverifiable", record_sha256: null, steps: [{ label: "Published key", ok: null, detail: "none" }] });
    render(<VerifyClient />);
    await choose(fileOf("{}"));
    expect(verifyEvidence.mock.calls[0][1]).toBeNull();
    expect(screen.getByText("Can't be verified here")).toBeInTheDocument();
  });

  it("a file that isn't JSON says so", async () => {
    render(<VerifyClient />);
    await choose(fileOf("%PDF-1.4", "report.pdf"));
    expect(screen.getByRole("alert")).toHaveTextContent("That file isn't JSON");
    expect(verifyEvidence).not.toHaveBeenCalled();
  });
});
