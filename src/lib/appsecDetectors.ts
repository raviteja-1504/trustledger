/**
 * Registers the expanded AppSec detectors (see appsecRules.ts) through detectorRegistry -- Kubernetes
 * hardening, cloud posture from Terraform/CloudFormation/ARM/Bicep/Serverless, container hardening, OpenAPI
 * specs, and endpoint auth consistency (GraphQL introspection is scanner.ts's own graphql-introspection-enabled). Imported for its side effects by scanner.ts, like
 * iacDetectors.ts and containerDetectors.ts.
 */
import { detectorRegistry } from "./detectorRegistry";
import { isKubernetesManifest } from "./iacKubernetes";
import { scanKubernetesScoped } from "./iac/kubernetesScoped";
import { scanTerraformCloud, scanCloudFormation, scanArmTemplate, scanBicep, scanServerless, isServerlessConfig } from "./iac/cloudPosture";
import { findDockerfileEolBaseImage, findDockerfileBuildRisks, findComposeRuntimeRisks } from "./containerHardening";
import { scanOpenApiSpec } from "./api/openapiSpec";
import { findEndpointMissingAuth } from "./api/apiInventory";

const CONFIG_LANGS = new Set(["yaml", "json"]);
const SOURCE_LANGS = new Set(["typescript", "javascript", "python", "java", "kotlin", "csharp", "golang", "php"]);

detectorRegistry.register({
  id: "appsec-kubernetes-scoped", category: "security",
  scan: ctx => ctx.language === "yaml" && isKubernetesManifest(ctx.content) ? scanKubernetesScoped(ctx.content) : [],
});
detectorRegistry.register({
  id: "appsec-cloud-terraform", category: "security",
  scan: ctx => ctx.language === "terraform" ? scanTerraformCloud(ctx.content) : [],
});
detectorRegistry.register({
  id: "appsec-cloud-cloudformation", category: "security",
  scan: ctx => CONFIG_LANGS.has(ctx.language) ? scanCloudFormation(ctx.content) : [],
});
detectorRegistry.register({
  id: "appsec-cloud-arm", category: "security",
  scan: ctx => ctx.language === "json" ? scanArmTemplate(ctx.content) : [],
});
detectorRegistry.register({
  id: "appsec-cloud-bicep", category: "security",
  scan: ctx => ctx.language === "bicep" ? scanBicep(ctx.content) : [],
});
detectorRegistry.register({
  id: "appsec-cloud-serverless", category: "security",
  scan: ctx => ctx.language === "yaml" && isServerlessConfig(ctx.file_path, ctx.content) ? scanServerless(ctx.content) : [],
});
detectorRegistry.register({
  id: "appsec-container-hardening", category: "security",
  scan: ctx => ctx.language === "dockerfile" ? [...findDockerfileEolBaseImage(ctx.content), ...findDockerfileBuildRisks(ctx.content)]
    : ctx.language === "yaml" ? findComposeRuntimeRisks(ctx.content) : [],
});
detectorRegistry.register({
  id: "appsec-openapi-spec", category: "security",
  scan: ctx => CONFIG_LANGS.has(ctx.language) && /\b(?:openapi|swagger)\b/.test(ctx.content.slice(0, 4000)) ? scanOpenApiSpec(ctx.content) : [],
});
detectorRegistry.register({
  id: "appsec-endpoint-auth", category: "security",
  scan: ctx => SOURCE_LANGS.has(ctx.language) ? findEndpointMissingAuth(ctx.file_path, ctx.content) : [],
});
