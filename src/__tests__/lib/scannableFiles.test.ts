import { isScannablePath, isLikelyK8sManifestPath } from "@/lib/scannableFiles";

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
