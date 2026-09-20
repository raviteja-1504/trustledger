import {
  isKubernetesManifest, findPrivilegedContainer, findContainerRunAsRoot,
  findHostNamespaceAccess, findDangerousCapability, findUnpinnedImageTag,
} from "@/lib/iacKubernetes";

const MANIFEST_PREFIX = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
      - name: app
`;

function wrap(securitySection: string): string {
  return `${MANIFEST_PREFIX}${securitySection}\n`;
}

describe("iacKubernetes.isKubernetesManifest", () => {
  it("recognizes a manifest with apiVersion + kind", () => {
    expect(isKubernetesManifest("apiVersion: v1\nkind: Pod\n")).toBe(true);
  });

  it("does not recognize an arbitrary YAML file", () => {
    expect(isKubernetesManifest("name: my-app\nversion: 1.0.0\n")).toBe(false);
  });

  it("recognizes a multi-document file where only one document is a manifest", () => {
    const content = "name: ci-config\nsteps: []\n---\napiVersion: v1\nkind: Pod\n";
    expect(isKubernetesManifest(content)).toBe(true);
  });
});

describe("iacKubernetes.findPrivilegedContainer", () => {
  it("flags privileged: true", () => {
    const content = wrap("        securityContext:\n          privileged: true");
    expect(findPrivilegedContainer(content).some(f => f.id === "iac-privileged-container")).toBe(true);
  });

  it("does not flag when privileged is absent", () => {
    const content = wrap("        securityContext:\n          readOnlyRootFilesystem: true");
    expect(findPrivilegedContainer(content)).toHaveLength(0);
  });

  it("does not fire on a non-manifest YAML file even if the text matches", () => {
    const content = "privileged: true\n"; // no apiVersion/kind at all
    expect(findPrivilegedContainer(content)).toHaveLength(0);
  });
});

describe("iacKubernetes.findContainerRunAsRoot", () => {
  it("flags runAsUser: 0", () => {
    const content = wrap("        securityContext:\n          runAsUser: 0");
    expect(findContainerRunAsRoot(content).some(f => f.id === "iac-container-run-as-root")).toBe(true);
  });

  it("flags runAsNonRoot: false", () => {
    const content = wrap("        securityContext:\n          runAsNonRoot: false");
    expect(findContainerRunAsRoot(content).some(f => f.id === "iac-container-run-as-root")).toBe(true);
  });

  it("does not flag runAsNonRoot: true", () => {
    const content = wrap("        securityContext:\n          runAsNonRoot: true");
    expect(findContainerRunAsRoot(content)).toHaveLength(0);
  });

  it("does not flag when no securityContext is set at all (explicit-bad-value only, no absence check)", () => {
    const content = wrap("        image: app:1.0");
    expect(findContainerRunAsRoot(content)).toHaveLength(0);
  });
});

describe("iacKubernetes.findHostNamespaceAccess", () => {
  it("flags hostNetwork: true", () => {
    const content = wrap("      hostNetwork: true");
    expect(findHostNamespaceAccess(content).some(f => f.id === "iac-host-namespace-access")).toBe(true);
  });

  it("flags hostPID: true", () => {
    const content = wrap("      hostPID: true");
    expect(findHostNamespaceAccess(content).some(f => f.id === "iac-host-namespace-access")).toBe(true);
  });

  it("does not flag hostNetwork: false", () => {
    const content = wrap("      hostNetwork: false");
    expect(findHostNamespaceAccess(content)).toHaveLength(0);
  });
});

describe("iacKubernetes.findDangerousCapability", () => {
  it("flags SYS_ADMIN added within a capabilities.add list", () => {
    const content = wrap("        securityContext:\n          capabilities:\n            add:\n            - SYS_ADMIN");
    expect(findDangerousCapability(content).some(f => f.id === "iac-dangerous-capability")).toBe(true);
  });

  it("flags ALL added", () => {
    const content = wrap("        securityContext:\n          capabilities:\n            add:\n            - ALL");
    expect(findDangerousCapability(content).some(f => f.id === "iac-dangerous-capability")).toBe(true);
  });

  it("does not flag a benign capability", () => {
    const content = wrap("        securityContext:\n          capabilities:\n            add:\n            - NET_BIND_SERVICE");
    expect(findDangerousCapability(content)).toHaveLength(0);
  });

  it("does not flag a dangerous-looking name with no nearby capabilities/add header", () => {
    const content = wrap("        env:\n        - name: MODE\n          value: SYS_ADMIN");
    // "- SYS_ADMIN" pattern requires a list-item shape ("- SYS_ADMIN"), not
    // "value: SYS_ADMIN" -- this case shouldn't even match DANGEROUS_CAP_RE,
    // confirming the regex itself (not just the window check) is scoped.
    expect(findDangerousCapability(content)).toHaveLength(0);
  });
});

describe("iacKubernetes.findUnpinnedImageTag", () => {
  it("flags an image with no tag", () => {
    const content = wrap("        image: nginx");
    expect(findUnpinnedImageTag(content).some(f => f.id === "iac-unpinned-image-tag")).toBe(true);
  });

  it("flags an image pinned to :latest", () => {
    const content = wrap("        image: nginx:latest");
    expect(findUnpinnedImageTag(content).some(f => f.id === "iac-unpinned-image-tag")).toBe(true);
  });

  it("does not flag an image pinned to a specific version", () => {
    const content = wrap("        image: nginx:1.25.3");
    expect(findUnpinnedImageTag(content)).toHaveLength(0);
  });

  it("does not flag an image pinned to a digest", () => {
    const content = wrap("        image: nginx@sha256:2ab30d7e6b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b");
    expect(findUnpinnedImageTag(content)).toHaveLength(0);
  });

  it("does not flag a registry-with-port image that IS tagged", () => {
    const content = wrap("        image: myregistry.local:5000/app:1.0");
    expect(findUnpinnedImageTag(content)).toHaveLength(0);
  });

  it("flags a registry-with-port image with no tag (port colon isn't a tag)", () => {
    const content = wrap("        image: myregistry.local:5000/app");
    expect(findUnpinnedImageTag(content).some(f => f.id === "iac-unpinned-image-tag")).toBe(true);
  });
});
