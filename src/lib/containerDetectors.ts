/**
 * Registers the Container security phase detectors (Dockerfile +
 * docker-compose.yml) through detectorRegistry, the plugin on-ramp
 * scanner.ts already calls via detectorRegistry.runAll() — see
 * detectorRegistry.ts's own docblock. Mirrors iacDetectors.ts exactly.
 *
 * Imported for its side effects only (scanner.ts does `import
 * "./containerDetectors";`), so registration always happens before any scan
 * runs, regardless of import ordering elsewhere.
 */

import { detectorRegistry } from "./detectorRegistry";
import {
  findDockerfileRunsAsRoot, findDockerfileUnpinnedBaseImage, findDockerfileRemoteAdd,
  findDockerfilePipedShellExec, findDockerfileHardcodedSecret, findDockerfileSensitiveCopy,
  findDockerfileExposedSensitivePort,
} from "./containerDockerfile";
import {
  findComposePrivileged, findComposeDockerSocketMount, findComposeHostNamespace,
  findComposeDangerousCapability, findComposeHardcodedSecret, findComposeUnpinnedImage,
} from "./containerCompose";

detectorRegistry.register({
  id: "container-runs-as-root", category: "security",
  scan: ctx => ctx.language === "dockerfile" ? findDockerfileRunsAsRoot(ctx.content) : [],
});
detectorRegistry.register({
  id: "container-unpinned-base-image", category: "security",
  scan: ctx => ctx.language === "dockerfile" ? findDockerfileUnpinnedBaseImage(ctx.content) : [],
});
detectorRegistry.register({
  id: "container-add-remote-url", category: "security",
  scan: ctx => ctx.language === "dockerfile" ? findDockerfileRemoteAdd(ctx.content) : [],
});
detectorRegistry.register({
  id: "container-piped-shell-exec", category: "security",
  scan: ctx => ctx.language === "dockerfile" ? findDockerfilePipedShellExec(ctx.content) : [],
});
detectorRegistry.register({
  id: "container-hardcoded-secret", category: "security",
  scan: ctx => ctx.language === "dockerfile" ? findDockerfileHardcodedSecret(ctx.content) : [],
});
detectorRegistry.register({
  id: "container-sensitive-file-copy", category: "security",
  scan: ctx => ctx.language === "dockerfile" ? findDockerfileSensitiveCopy(ctx.content) : [],
});
detectorRegistry.register({
  id: "container-exposed-sensitive-port", category: "security",
  scan: ctx => ctx.language === "dockerfile" ? findDockerfileExposedSensitivePort(ctx.content) : [],
});

detectorRegistry.register({
  id: "container-compose-privileged", category: "security",
  scan: ctx => ctx.language === "yaml" ? findComposePrivileged(ctx.content) : [],
});
detectorRegistry.register({
  id: "container-compose-docker-socket-mount", category: "security",
  scan: ctx => ctx.language === "yaml" ? findComposeDockerSocketMount(ctx.content) : [],
});
detectorRegistry.register({
  id: "container-compose-host-namespace", category: "security",
  scan: ctx => ctx.language === "yaml" ? findComposeHostNamespace(ctx.content) : [],
});
detectorRegistry.register({
  id: "container-compose-dangerous-capability", category: "security",
  scan: ctx => ctx.language === "yaml" ? findComposeDangerousCapability(ctx.content) : [],
});
detectorRegistry.register({
  id: "container-compose-hardcoded-secret", category: "security",
  scan: ctx => ctx.language === "yaml" ? findComposeHardcodedSecret(ctx.content) : [],
});
detectorRegistry.register({
  id: "container-compose-unpinned-image", category: "security",
  scan: ctx => ctx.language === "yaml" ? findComposeUnpinnedImage(ctx.content) : [],
});
