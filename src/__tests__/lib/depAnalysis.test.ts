import { parseComposerJson, parseCsproj } from "@/lib/depAnalysis";

describe("parseComposerJson", () => {
  it("parses require and require-dev, marking dev packages", () => {
    const content = JSON.stringify({
      require: { php: ">=8.1", "guzzlehttp/guzzle": "^7.5.0" },
      "require-dev": { "phpunit/phpunit": "^10.0" },
    });
    const refs = parseComposerJson(content);
    expect(refs).toEqual(expect.arrayContaining([
      { name: "guzzlehttp/guzzle", version: "^7.5.0", dev: false },
      { name: "phpunit/phpunit", version: "^10.0", dev: true },
    ]));
  });

  it("excludes platform requirements (php, ext-*, lib-*)", () => {
    const content = JSON.stringify({
      require: { php: ">=8.1", "ext-json": "*", "ext-mbstring": "*", "monolog/monolog": "^3.0" },
    });
    const refs = parseComposerJson(content);
    expect(refs.map(r => r.name)).toEqual(["monolog/monolog"]);
  });

  it("returns [] for malformed JSON rather than throwing", () => {
    expect(parseComposerJson("{not json")).toEqual([]);
  });
});

describe("parseCsproj", () => {
  it("parses self-closing PackageReference elements with a Version attribute", () => {
    const content = `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="Serilog" Version="2.10.0" />
  </ItemGroup>
</Project>`;
    expect(parseCsproj(content)).toEqual([
      { name: "Newtonsoft.Json", version: "13.0.1", dev: false },
      { name: "Serilog", version: "2.10.0", dev: false },
    ]);
  });

  it("parses a nested <Version> child element", () => {
    const content = `<PackageReference Include="Newtonsoft.Json">
  <Version>13.0.1</Version>
</PackageReference>`;
    expect(parseCsproj(content)).toEqual([{ name: "Newtonsoft.Json", version: "13.0.1", dev: false }]);
  });

  it("reports \"*\" for an unpinned PackageReference (central package management)", () => {
    const content = `<PackageReference Include="Newtonsoft.Json" />`;
    expect(parseCsproj(content)).toEqual([{ name: "Newtonsoft.Json", version: "*", dev: false }]);
  });

  it("returns [] when there are no PackageReference elements", () => {
    expect(parseCsproj(`<Project><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>`)).toEqual([]);
  });
});
