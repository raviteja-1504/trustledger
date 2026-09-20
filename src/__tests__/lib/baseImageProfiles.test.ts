import { matchBaseImageProfile, packagesForProfile } from "@/lib/baseImageProfiles";

describe("baseImageProfiles.matchBaseImageProfile", () => {
  it("matches a plain curated tag", () => {
    const profile = matchBaseImageProfile("node:20-alpine");
    expect(profile).toEqual({ ecosystem: "Alpine", osvEcosystem: "Alpine:v3.19" });
  });

  it("matches a Debian-based curated tag", () => {
    const profile = matchBaseImageProfile("postgres:16");
    expect(profile?.ecosystem).toBe("Debian");
    expect(profile?.osvEcosystem).toBe("Debian:12");
  });

  it("matches an Ubuntu-based curated tag", () => {
    const profile = matchBaseImageProfile("ubuntu:22.04");
    expect(profile?.osvEcosystem).toBe("Ubuntu:22.04:LTS");
  });

  it("strips a registry/namespace prefix before matching", () => {
    const profile = matchBaseImageProfile("docker.io/library/node:20-alpine");
    expect(profile?.osvEcosystem).toBe("Alpine:v3.19");
  });

  it("strips a trailing digest before matching", () => {
    const profile = matchBaseImageProfile("node:20-alpine@sha256:2ab30d7e6b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b");
    expect(profile?.osvEcosystem).toBe("Alpine:v3.19");
  });

  it("returns null for an uncurated/arbitrary image", () => {
    expect(matchBaseImageProfile("my-private-registry.internal/custom-app:v3")).toBeNull();
  });

  it("returns null for an unpinned bare image name not in the table", () => {
    expect(matchBaseImageProfile("some-random-tool")).toBeNull();
  });
});

describe("baseImageProfiles.packagesForProfile", () => {
  it("returns a non-empty package list for an Alpine profile", () => {
    const profile = matchBaseImageProfile("alpine:3.19")!;
    const packages = packagesForProfile(profile);
    expect(packages.length).toBeGreaterThan(0);
    expect(packages).toContain("openssl");
  });

  it("returns a non-empty package list for a Debian profile", () => {
    const profile = matchBaseImageProfile("debian:12")!;
    const packages = packagesForProfile(profile);
    expect(packages.length).toBeGreaterThan(0);
    expect(packages).toContain("libc6");
  });
});
