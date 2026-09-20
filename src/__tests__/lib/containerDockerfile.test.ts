import {
  isDockerfileContent, findDockerfileRunsAsRoot, findDockerfileUnpinnedBaseImage,
  findDockerfileRemoteAdd, findDockerfilePipedShellExec, findDockerfileHardcodedSecret,
  findDockerfileSensitiveCopy, findDockerfileExposedSensitivePort,
} from "@/lib/containerDockerfile";

describe("containerDockerfile.isDockerfileContent", () => {
  it("recognizes a file with a FROM instruction", () => {
    expect(isDockerfileContent("FROM node:20\nCMD [\"node\", \"app.js\"]\n")).toBe(true);
  });

  it("does not recognize an arbitrary file with no FROM instruction", () => {
    expect(isDockerfileContent("echo hello\n")).toBe(false);
  });
});

describe("containerDockerfile.findDockerfileRunsAsRoot", () => {
  it("flags a Dockerfile with no USER instruction at all", () => {
    const content = "FROM node:20\nCOPY . .\nCMD [\"node\", \"app.js\"]\n";
    expect(findDockerfileRunsAsRoot(content).some(f => f.id === "container-runs-as-root")).toBe(true);
  });

  it("flags USER root explicitly", () => {
    const content = "FROM node:20\nUSER root\nCMD [\"node\", \"app.js\"]\n";
    expect(findDockerfileRunsAsRoot(content).some(f => f.id === "container-runs-as-root")).toBe(true);
  });

  it("flags USER 0", () => {
    const content = "FROM node:20\nUSER 0\nCMD [\"node\", \"app.js\"]\n";
    expect(findDockerfileRunsAsRoot(content).some(f => f.id === "container-runs-as-root")).toBe(true);
  });

  it("does not flag a non-root USER", () => {
    const content = "FROM node:20\nUSER app\nCMD [\"node\", \"app.js\"]\n";
    expect(findDockerfileRunsAsRoot(content)).toHaveLength(0);
  });

  it("only considers the LAST build stage in a multi-stage Dockerfile", () => {
    // Early throwaway build stage runs as root (fine -- never ships), final
    // stage correctly switches to a non-root user.
    const content = [
      "FROM node:20 AS build",
      "USER root",
      "RUN npm run build",
      "FROM node:20-alpine",
      "USER app",
      "COPY --from=build /app/dist /app/dist",
    ].join("\n");
    expect(findDockerfileRunsAsRoot(content)).toHaveLength(0);
  });

  it("flags when the FINAL stage has no USER even though an earlier stage did", () => {
    const content = [
      "FROM node:20 AS build",
      "USER app",
      "RUN npm run build",
      "FROM node:20-alpine",
      "COPY --from=build /app/dist /app/dist",
    ].join("\n");
    expect(findDockerfileRunsAsRoot(content).some(f => f.id === "container-runs-as-root")).toBe(true);
  });

  it("does not fire on a non-Dockerfile with no FROM instruction", () => {
    expect(findDockerfileRunsAsRoot("echo hello\n")).toHaveLength(0);
  });
});

describe("containerDockerfile.findDockerfileUnpinnedBaseImage", () => {
  it("flags an image with no tag", () => {
    const content = "FROM node\n";
    expect(findDockerfileUnpinnedBaseImage(content).some(f => f.id === "container-unpinned-base-image")).toBe(true);
  });

  it("flags an image pinned to :latest", () => {
    const content = "FROM node:latest\n";
    expect(findDockerfileUnpinnedBaseImage(content).some(f => f.id === "container-unpinned-base-image")).toBe(true);
  });

  it("does not flag an image pinned to a specific version", () => {
    const content = "FROM node:20.11.1-alpine\n";
    expect(findDockerfileUnpinnedBaseImage(content)).toHaveLength(0);
  });

  it("does not flag an image pinned to a digest", () => {
    const content = "FROM node@sha256:2ab30d7e6b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b\n";
    expect(findDockerfileUnpinnedBaseImage(content)).toHaveLength(0);
  });

  it("does not flag FROM scratch", () => {
    const content = "FROM scratch\n";
    expect(findDockerfileUnpinnedBaseImage(content)).toHaveLength(0);
  });

  it("does not flag a later stage referencing an earlier AS-aliased stage by name", () => {
    const content = "FROM node:20.11.1-alpine AS build\nRUN npm run build\nFROM build\nCMD [\"node\", \"app.js\"]\n";
    expect(findDockerfileUnpinnedBaseImage(content)).toHaveLength(0);
  });
});

describe("containerDockerfile.findDockerfileRemoteAdd", () => {
  it("flags ADD from an http(s) URL", () => {
    const content = "FROM node:20\nADD https://example.com/install.sh /install.sh\n";
    expect(findDockerfileRemoteAdd(content).some(f => f.id === "container-add-remote-url")).toBe(true);
  });

  it("does not flag ADD of a local file", () => {
    const content = "FROM node:20\nADD ./package.json /app/package.json\n";
    expect(findDockerfileRemoteAdd(content)).toHaveLength(0);
  });

  it("does not flag COPY (not ADD) of a URL-shaped string argument", () => {
    const content = "FROM node:20\nCOPY README.md /app/README.md\n";
    expect(findDockerfileRemoteAdd(content)).toHaveLength(0);
  });
});

describe("containerDockerfile.findDockerfilePipedShellExec", () => {
  it("flags curl | sh", () => {
    const content = "FROM node:20\nRUN curl -fsSL https://example.com/install.sh | sh\n";
    expect(findDockerfilePipedShellExec(content).some(f => f.id === "container-piped-shell-exec")).toBe(true);
  });

  it("flags wget | bash", () => {
    const content = "FROM node:20\nRUN wget -qO- https://example.com/install.sh | bash\n";
    expect(findDockerfilePipedShellExec(content).some(f => f.id === "container-piped-shell-exec")).toBe(true);
  });

  it("does not flag a curl call with no pipe to a shell", () => {
    const content = "FROM node:20\nRUN curl -fsSL https://example.com/install.sh -o install.sh\n";
    expect(findDockerfilePipedShellExec(content)).toHaveLength(0);
  });
});

describe("containerDockerfile.findDockerfileHardcodedSecret", () => {
  it("flags a hardcoded secret in an ENV instruction", () => {
    const content = "FROM node:20\nENV API_KEY=sk_live_abc123def456\n";
    expect(findDockerfileHardcodedSecret(content).some(f => f.id === "container-hardcoded-secret")).toBe(true);
  });

  it("flags a hardcoded secret in an ARG instruction", () => {
    const content = "FROM node:20\nARG DB_PASSWORD=hunter2hunter2\n";
    expect(findDockerfileHardcodedSecret(content).some(f => f.id === "container-hardcoded-secret")).toBe(true);
  });

  it("does not flag a non-credential-shaped ENV/ARG name", () => {
    const content = "FROM node:20\nENV NODE_ENV=production\n";
    expect(findDockerfileHardcodedSecret(content)).toHaveLength(0);
  });

  it("does not flag an ARG that only declares the name with no default value", () => {
    const content = "FROM node:20\nARG API_KEY\n";
    expect(findDockerfileHardcodedSecret(content)).toHaveLength(0);
  });

  it("does not flag a variable-reference value", () => {
    const content = "FROM node:20\nARG API_KEY\nENV API_KEY=${API_KEY}\n";
    expect(findDockerfileHardcodedSecret(content)).toHaveLength(0);
  });
});

describe("containerDockerfile.findDockerfileSensitiveCopy", () => {
  it("flags COPY of a .env file", () => {
    const content = "FROM node:20\nCOPY .env /app/.env\n";
    expect(findDockerfileSensitiveCopy(content).some(f => f.id === "container-sensitive-file-copy")).toBe(true);
  });

  it("flags COPY of an id_rsa private key", () => {
    const content = "FROM node:20\nCOPY id_rsa /root/.ssh/id_rsa\n";
    expect(findDockerfileSensitiveCopy(content).some(f => f.id === "container-sensitive-file-copy")).toBe(true);
  });

  it("does not flag COPY of an ordinary application file", () => {
    const content = "FROM node:20\nCOPY package.json /app/package.json\n";
    expect(findDockerfileSensitiveCopy(content)).toHaveLength(0);
  });
});

describe("containerDockerfile.findDockerfileExposedSensitivePort", () => {
  it("flags EXPOSE 22 (SSH)", () => {
    const content = "FROM node:20\nEXPOSE 22\n";
    expect(findDockerfileExposedSensitivePort(content).some(f => f.id === "container-exposed-sensitive-port")).toBe(true);
  });

  it("does not flag an ordinary application port", () => {
    const content = "FROM node:20\nEXPOSE 3000\n";
    expect(findDockerfileExposedSensitivePort(content)).toHaveLength(0);
  });
});
