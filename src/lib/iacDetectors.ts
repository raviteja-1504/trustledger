/**
 * Registers the IaC security Phase 3 detectors (Terraform + Kubernetes)
 * through detectorRegistry, the plugin on-ramp scanner.ts already calls via
 * detectorRegistry.runAll() — see detectorRegistry.ts's own docblock.
 *
 * Imported for its side effects only (scanner.ts does `import
 * "./iacDetectors";`), so registration always happens before any scan runs,
 * regardless of import ordering elsewhere.
 */

import { detectorRegistry } from "./detectorRegistry";
import {
  findS3PublicAcl, findOpenIngress, findUnencryptedStorage, findIamWildcard, findPublicDb,
} from "./iacTerraform";
import {
  findPrivilegedContainer, findContainerRunAsRoot, findHostNamespaceAccess,
  findDangerousCapability, findUnpinnedImageTag,
} from "./iacKubernetes";

detectorRegistry.register({
  id: "iac-s3-public-acl", category: "security",
  scan: ctx => ctx.language === "terraform" ? findS3PublicAcl(ctx.content) : [],
});
detectorRegistry.register({
  id: "iac-open-ingress", category: "security",
  scan: ctx => ctx.language === "terraform" ? findOpenIngress(ctx.content) : [],
});
detectorRegistry.register({
  id: "iac-unencrypted-storage", category: "security",
  scan: ctx => ctx.language === "terraform" ? findUnencryptedStorage(ctx.content) : [],
});
detectorRegistry.register({
  id: "iac-iam-wildcard", category: "security",
  scan: ctx => ctx.language === "terraform" ? findIamWildcard(ctx.content) : [],
});
detectorRegistry.register({
  id: "iac-public-db", category: "security",
  scan: ctx => ctx.language === "terraform" ? findPublicDb(ctx.content) : [],
});

detectorRegistry.register({
  id: "iac-privileged-container", category: "security",
  scan: ctx => ctx.language === "yaml" ? findPrivilegedContainer(ctx.content) : [],
});
detectorRegistry.register({
  id: "iac-container-run-as-root", category: "security",
  scan: ctx => ctx.language === "yaml" ? findContainerRunAsRoot(ctx.content) : [],
});
detectorRegistry.register({
  id: "iac-host-namespace-access", category: "security",
  scan: ctx => ctx.language === "yaml" ? findHostNamespaceAccess(ctx.content) : [],
});
detectorRegistry.register({
  id: "iac-dangerous-capability", category: "security",
  scan: ctx => ctx.language === "yaml" ? findDangerousCapability(ctx.content) : [],
});
detectorRegistry.register({
  id: "iac-unpinned-image-tag", category: "security",
  scan: ctx => ctx.language === "yaml" ? findUnpinnedImageTag(ctx.content) : [],
});
