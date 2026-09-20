import {
  isComposeContent, findComposePrivileged, findComposeDockerSocketMount,
  findComposeHostNamespace, findComposeDangerousCapability, findComposeHardcodedSecret,
  findComposeUnpinnedImage,
} from "@/lib/containerCompose";

const COMPOSE_PREFIX = `
services:
  app:
`;

function wrap(serviceBody: string): string {
  return `${COMPOSE_PREFIX}${serviceBody}\n`;
}

describe("containerCompose.isComposeContent", () => {
  it("recognizes a file with a top-level services: key", () => {
    expect(isComposeContent("services:\n  app:\n    image: nginx\n")).toBe(true);
  });

  it("does not recognize an arbitrary YAML file", () => {
    expect(isComposeContent("name: my-app\nversion: 1.0.0\n")).toBe(false);
  });

  it("does not recognize a Kubernetes manifest (no top-level services: key)", () => {
    expect(isComposeContent("apiVersion: v1\nkind: Pod\n")).toBe(false);
  });
});

describe("containerCompose.findComposePrivileged", () => {
  it("flags privileged: true", () => {
    const content = wrap("    privileged: true");
    expect(findComposePrivileged(content).some(f => f.id === "container-compose-privileged")).toBe(true);
  });

  it("does not flag when privileged is absent", () => {
    const content = wrap("    image: nginx:1.25.3");
    expect(findComposePrivileged(content)).toHaveLength(0);
  });

  it("does not fire on a non-compose YAML file even if the text matches", () => {
    const content = "privileged: true\n"; // no top-level services: key
    expect(findComposePrivileged(content)).toHaveLength(0);
  });
});

describe("containerCompose.findComposeDockerSocketMount", () => {
  it("flags a docker.sock volume mount", () => {
    const content = wrap("    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock");
    expect(findComposeDockerSocketMount(content).some(f => f.id === "container-compose-docker-socket-mount")).toBe(true);
  });

  it("does not flag an ordinary volume mount", () => {
    const content = wrap("    volumes:\n      - ./data:/app/data");
    expect(findComposeDockerSocketMount(content)).toHaveLength(0);
  });
});

describe("containerCompose.findComposeHostNamespace", () => {
  it("flags network_mode: host", () => {
    const content = wrap("    network_mode: host");
    expect(findComposeHostNamespace(content).some(f => f.id === "container-compose-host-namespace")).toBe(true);
  });

  it("flags pid: host", () => {
    const content = wrap("    pid: host");
    expect(findComposeHostNamespace(content).some(f => f.id === "container-compose-host-namespace")).toBe(true);
  });

  it("does not flag network_mode: bridge", () => {
    const content = wrap("    network_mode: bridge");
    expect(findComposeHostNamespace(content)).toHaveLength(0);
  });
});

describe("containerCompose.findComposeDangerousCapability", () => {
  it("flags SYS_ADMIN added within a cap_add list", () => {
    const content = wrap("    cap_add:\n      - SYS_ADMIN");
    expect(findComposeDangerousCapability(content).some(f => f.id === "container-compose-dangerous-capability")).toBe(true);
  });

  it("does not flag a benign capability", () => {
    const content = wrap("    cap_add:\n      - NET_BIND_SERVICE");
    expect(findComposeDangerousCapability(content)).toHaveLength(0);
  });

  it("does not flag a dangerous-looking name with no nearby cap_add header", () => {
    const content = wrap("    environment:\n      - MODE=SYS_ADMIN");
    expect(findComposeDangerousCapability(content)).toHaveLength(0);
  });
});

describe("containerCompose.findComposeHardcodedSecret", () => {
  it("flags a hardcoded secret in an environment: list item", () => {
    const content = wrap("    environment:\n      - DB_PASSWORD=hunter2hunter2");
    expect(findComposeHardcodedSecret(content).some(f => f.id === "container-compose-hardcoded-secret")).toBe(true);
  });

  it("flags a hardcoded secret in an environment: map item", () => {
    const content = wrap("    environment:\n      DB_PASSWORD: hunter2hunter2");
    expect(findComposeHardcodedSecret(content).some(f => f.id === "container-compose-hardcoded-secret")).toBe(true);
  });

  it("does not flag a non-credential-shaped environment variable", () => {
    const content = wrap("    environment:\n      - NODE_ENV=production");
    expect(findComposeHardcodedSecret(content)).toHaveLength(0);
  });

  it("does not flag a variable-reference value", () => {
    const content = wrap("    environment:\n      - DB_PASSWORD=${DB_PASSWORD}");
    expect(findComposeHardcodedSecret(content)).toHaveLength(0);
  });
});

describe("containerCompose.findComposeUnpinnedImage", () => {
  it("flags an image with no tag", () => {
    const content = wrap("    image: nginx");
    expect(findComposeUnpinnedImage(content).some(f => f.id === "container-compose-unpinned-image")).toBe(true);
  });

  it("flags an image pinned to :latest", () => {
    const content = wrap("    image: nginx:latest");
    expect(findComposeUnpinnedImage(content).some(f => f.id === "container-compose-unpinned-image")).toBe(true);
  });

  it("does not flag an image pinned to a specific version", () => {
    const content = wrap("    image: nginx:1.25.3");
    expect(findComposeUnpinnedImage(content)).toHaveLength(0);
  });

  it("does not flag an image pinned to a digest", () => {
    const content = wrap("    image: nginx@sha256:2ab30d7e6b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b");
    expect(findComposeUnpinnedImage(content)).toHaveLength(0);
  });
});
