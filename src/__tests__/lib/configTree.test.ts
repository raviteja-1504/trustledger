import { parseYamlDocuments, parseJsonTree, parseConfigDocuments, get, path, str, bool, items, strings, entryLine } from "@/lib/iac/configTree";

const K8S = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web   # trailing comment
spec:
  template:
    spec:
      containers:
      - name: app
        image: "nginx:1.25"
        securityContext:
          allowPrivilegeEscalation: false
        env:
          - name: DB_PASSWORD
            value: hunter2
      - name: sidecar
        image: busybox
        args: ["sh", "-c", "echo hi"]
      volumes:
      - name: data
        hostPath: { path: /var/run/docker.sock }
---
kind: Service
`;

describe("YAML", () => {
  const [dep, svc] = parseYamlDocuments(K8S);
  it("documents, nested maps, sequences of maps, and line numbers", () => {
    expect(str(get(dep, "kind"))).toBe("Deployment");
    expect(str(path(dep, "metadata", "name"))).toBe("web");
    const cs = items(path(dep, "spec", "template", "spec", "containers"));
    expect(cs.map(c => str(get(c, "name")))).toEqual(["app", "sidecar"]);
    expect(cs[0].line).toBe(9);
    expect(str(get(cs[0], "image"))).toBe("nginx:1.25");
    expect(bool(path(cs[0], "securityContext", "allowPrivilegeEscalation"))).toBe(false);
    const env = items(get(cs[0], "env"));
    expect(str(get(env[0], "value"))).toBe("hunter2");
    expect(entryLine(env[0], "value")).toBe(15);
    expect(strings(get(cs[1], "args"))).toEqual(["sh", "-c", "echo hi"]);
    expect(str(path(items(path(dep, "spec", "template", "spec", "volumes"))[0], "hostPath", "path"))).toBe("/var/run/docker.sock");
    expect(str(get(svc, "kind"))).toBe("Service");
  });
  it("a sequence at the same indentation as its key, block scalars, CloudFormation tags, Helm lines", () => {
    const [d] = parseYamlDocuments(`Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: !Sub "\${AWS::StackName}-b"\n      Tags:\n      - Key: a\n        Value: b\n    Script: |\n      echo 1\n      echo 2\n{{- if .Values.x }}\n  C:\n    Type: AWS::SQS::Queue\n{{- end }}\n`);
    expect(str(path(d, "Resources", "B", "Type"))).toBe("AWS::S3::Bucket");
    expect(str(path(d, "Resources", "B", "Properties", "BucketName"))).toContain("!Sub");
    expect(items(path(d, "Resources", "B", "Properties", "Tags")).map(t => str(get(t, "Key")))).toEqual(["a"]);
    expect(str(path(d, "Resources", "B", "Script"))).toBe("echo 1\necho 2");
    expect(str(path(d, "Resources", "C", "Type"))).toBe("AWS::SQS::Queue");
  });
  it("never throws on garbage", () => {
    expect(() => parseYamlDocuments("::: - [ {\n  - : :\n\t\t-")).not.toThrow();
  });
});

describe("JSON", () => {
  it("objects, arrays, scalars with line numbers; invalid JSON is null", () => {
    const j = parseJsonTree(`{\n  "a": {\n    "b": [1, "x", true]\n  },\n  "c": "d"\n}`);
    expect(strings(path(j!, "a", "b"))).toEqual(["1", "x", "true"]);
    expect(entryLine(j!, "c")).toBe(5);
    expect(entryLine(get(j!, "a"), "b")).toBe(3);
    expect(parseJsonTree("{ nope")).toBeNull();
  });
  it("parseConfigDocuments picks JSON or YAML by content", () => {
    expect(str(get(parseConfigDocuments(`{"openapi":"3.0.0"}`)[0], "openapi"))).toBe("3.0.0");
    expect(str(get(parseConfigDocuments(`openapi: 3.0.0\n`)[0], "openapi"))).toBe("3.0.0");
  });
});
