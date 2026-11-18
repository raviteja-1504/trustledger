/**
 * Swagger UI for /docs/api comes from a public CDN, so it is pinned to one exact version and each file carries a Subresource
 * Integrity hash: if the package were ever tampered with, the browser refuses to run it.
 *
 * To upgrade: change SWAGGER_VERSION, then recompute both hashes from the published files:
 *   npm pack swagger-ui-dist@<version>   (extract package/swagger-ui.css and package/swagger-ui-bundle.js)
 *   openssl dgst -sha384 -binary <file> | openssl base64 -A      (prefix the result with "sha384-")
 * The test in __tests__/lib/swaggerAssets.test.ts fails if the URLs drift from a pinned version or a hash is missing.
 */
export const SWAGGER_VERSION = "5.35.0";
export const SWAGGER_CSS_URL = `https://unpkg.com/swagger-ui-dist@${SWAGGER_VERSION}/swagger-ui.css`;
export const SWAGGER_JS_URL  = `https://unpkg.com/swagger-ui-dist@${SWAGGER_VERSION}/swagger-ui-bundle.js`;
export const SWAGGER_CSS_SRI = "sha384-WlYgdmXYOOBWL5apwjDEZwN+U3HmXSSu5R6V5aGxEcf7z+KuRNwBhoxKVN1i3D5I";
export const SWAGGER_JS_SRI  = "sha384-gjRm0bEPMeTmMh5jT2cHccIwCUZSTd8YC+j0d0sXw0MdGEfScduGpSyF3ZSSLkX9";
