import { isScannablePath, isLikelyK8sManifestPath, isDockerfilePath, isDockerComposePath } from "@/lib/scannableFiles";

describe("scannableFiles.isScannablePath", () => {
  it("scans a .tf file by extension", () => {
    expect(isScannablePath("infra/main.tf")).toBe(true);
  });

  it("scans a .tfvars file by extension", () => {
    expect(isScannablePath("infra/prod.tfvars")).toBe(true);
  });

  it("scans an existing source extension unaffected by the IaC additions", () => {
    expect(isScannablePath("src/app.ts")).toBe(true);
  });

  it("does not scan an arbitrary .yaml file with no IaC path/name hint", () => {
    expect(isScannablePath("config/settings.yaml")).toBe(false);
  });

  it("scans a .yaml file under a k8s/ directory", () => {
    expect(isScannablePath("k8s/app.yaml")).toBe(true);
  });

  it("scans a .yaml file matching a common manifest basename outside any hinted directory", () => {
    expect(isScannablePath("random/dir/deployment.yaml")).toBe(true);
  });

  it("does not scan an unrelated file type", () => {
    expect(isScannablePath("README.md")).toBe(false);
  });

  it("scans a .csproj file regardless of its project-specific basename", () => {
    expect(isScannablePath("src/Api/Api.csproj")).toBe(true);
    expect(isScannablePath("SomeOtherProject.csproj")).toBe(true);
  });

  it("scans composer.json", () => {
    expect(isScannablePath("composer.json")).toBe(true);
  });

  it("scans a bare Dockerfile despite having no extension", () => {
    expect(isScannablePath("Dockerfile")).toBe(true);
  });

  it("scans a Dockerfile.prod variant", () => {
    expect(isScannablePath("docker/Dockerfile.prod")).toBe(true);
  });

  it("scans docker-compose.yml", () => {
    expect(isScannablePath("docker-compose.yml")).toBe(true);
  });

  it("scans a docker-compose.override.yaml variant", () => {
    expect(isScannablePath("docker-compose.override.yaml")).toBe(true);
  });
});

describe("scannableFiles.isDockerfilePath", () => {
  it("matches a bare Dockerfile", () => {
    expect(isDockerfilePath("Dockerfile")).toBe(true);
  });

  it("matches Dockerfile under a subdirectory", () => {
    expect(isDockerfilePath("services/api/Dockerfile")).toBe(true);
  });

  it("matches Dockerfile.dev", () => {
    expect(isDockerfilePath("Dockerfile.dev")).toBe(true);
  });

  it("matches a *.dockerfile extension variant", () => {
    expect(isDockerfilePath("backend.dockerfile")).toBe(true);
  });

  it("does not match an unrelated file", () => {
    expect(isDockerfilePath("README.md")).toBe(false);
  });
});

describe("scannableFiles.isDockerComposePath", () => {
  it("matches docker-compose.yml", () => {
    expect(isDockerComposePath("docker-compose.yml")).toBe(true);
  });

  it("matches docker-compose.yaml", () => {
    expect(isDockerComposePath("docker-compose.yaml")).toBe(true);
  });

  it("matches an environment-suffixed variant (docker-compose.prod.yml)", () => {
    expect(isDockerComposePath("docker-compose.prod.yml")).toBe(true);
  });

  it("matches the Compose V2 canonical name (compose.yaml)", () => {
    expect(isDockerComposePath("compose.yaml")).toBe(true);
  });

  it("does not match an arbitrary YAML file", () => {
    expect(isDockerComposePath("config/settings.yaml")).toBe(false);
  });
});

describe("scannableFiles.isLikelyK8sManifestPath", () => {
  it("matches by directory hint (kubernetes/)", () => {
    expect(isLikelyK8sManifestPath("kubernetes/deployment.yaml")).toBe(true);
  });

  it("matches by directory hint (deploy/)", () => {
    expect(isLikelyK8sManifestPath("deploy/service.yml")).toBe(true);
  });

  it("matches by directory hint (charts/, Helm convention)", () => {
    expect(isLikelyK8sManifestPath("charts/myapp/templates/ingress.yaml")).toBe(true);
  });

  it("matches by basename (values.yaml, Helm convention) even outside a hinted directory", () => {
    expect(isLikelyK8sManifestPath("myapp/values.yaml")).toBe(true);
  });

  it("matches by basename (kustomization.yaml)", () => {
    expect(isLikelyK8sManifestPath("overlays/prod/kustomization.yaml")).toBe(true);
  });

  it("does not match a random YAML file with no path/name hint", () => {
    expect(isLikelyK8sManifestPath("some/random/dir/config.yaml")).toBe(false);
  });

  it("does not match a GitHub Actions workflow file", () => {
    expect(isLikelyK8sManifestPath(".github/workflows/ci.yaml")).toBe(false);
  });

  it("does not match a non-YAML file even under a hinted directory", () => {
    expect(isLikelyK8sManifestPath("k8s/README.md")).toBe(false);
  });
});
