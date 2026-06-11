import { PERMISSIONS, ROLE_LABELS, ROLE_COLORS } from "@/lib/roles";

describe("roles lib", () => {

  it("developer cannot manage settings or users", () => {
    expect(PERMISSIONS.developer.canManageSettings).toBe(false);
    expect(PERMISSIONS.developer.canManageUsers).toBe(false);
  });

  it("developer can scan but not attest", () => {
    expect(PERMISSIONS.developer.canAttest).toBe(false);
    expect(PERMISSIONS.developer.canScan).toBe(true);
  });

  it("security_reviewer can attest but cannot manage settings", () => {
    expect(PERMISSIONS.security_reviewer.canAttest).toBe(true);
    expect(PERMISSIONS.security_reviewer.canManageSettings).toBe(false);
  });

  it("admin has all permissions", () => {
    const p = PERMISSIONS.admin;
    expect(p.canAttest).toBe(true);
    expect(p.canScan).toBe(true);
    expect(p.canManageSettings).toBe(true);
    expect(p.canManageUsers).toBe(true);
    expect(p.canExportData).toBe(true);
  });

  it("ROLE_LABELS has entries for all three roles", () => {
    expect(ROLE_LABELS.developer).toBeTruthy();
    expect(ROLE_LABELS.security_reviewer).toBeTruthy();
    expect(ROLE_LABELS.admin).toBeTruthy();
  });

  it("ROLE_COLORS provides bg/text/dot for all roles", () => {
    (["developer","security_reviewer","admin"] as const).forEach(role => {
      const c = ROLE_COLORS[role];
      expect(c.bg).toBeTruthy();
      expect(c.text).toBeTruthy();
      expect(c.dot).toBeTruthy();
    });
  });
});
