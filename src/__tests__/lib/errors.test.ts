/**
 * @jest-environment node
 *
 * errors.ts imports next/server (NextResponse), which needs the Fetch API
 * globals (Request/Response/Headers). jsdom (this project's default test
 * environment) doesn't implement them; Node's environment does natively.
 */
import { safeError } from "@/lib/errors";

describe("safeError", () => {
  it("never leaks the raw error message to the response body", async () => {
    const err = new Error("duplicate key value violates unique constraint \"users_email_key\" (Key (email)=(secret@internal.corp) already exists)");
    const res = await safeError(err, { code: "signup_failed", message: "We couldn't complete that action. Please try again." });
    const body = await res.json();

    expect(JSON.stringify(body)).not.toContain("secret@internal.corp");
    expect(JSON.stringify(body)).not.toContain("users_email_key");
    expect(body).toEqual({
      error:   "signup_failed",
      message: "We couldn't complete that action. Please try again.",
      ref_id:  expect.any(String),
    });
  });

  it("defaults to a 500 status but honors an explicit one", async () => {
    const res1 = await safeError(new Error("x"), { code: "c", message: "m" });
    expect(res1.status).toBe(500);

    const res2 = await safeError(new Error("x"), { code: "c", message: "m", status: 502 });
    expect(res2.status).toBe(502);
  });

  it("produces a distinct ref_id per call for log correlation", async () => {
    const res1 = await safeError(new Error("a"), { code: "c", message: "m" });
    const res2 = await safeError(new Error("b"), { code: "c", message: "m" });
    const body1 = await res1.json();
    const body2 = await res2.json();
    expect(body1.ref_id).not.toEqual(body2.ref_id);
  });

  it("handles a Supabase/PostgREST-style error object (no Error instance)", async () => {
    const pgErr = { message: "permission denied for table scans", code: "42501", details: null, hint: null };
    const res = await safeError(pgErr, { code: "fetch_failed", message: "We couldn't load that right now." });
    const body = await res.json();
    expect(JSON.stringify(body)).not.toContain("permission denied");
    expect(body.error).toBe("fetch_failed");
  });

  it("handles a completely non-object thrown value without crashing", async () => {
    const res = await safeError("just a string", { code: "c", message: "m" });
    expect(res.status).toBe(500);
  });
});
