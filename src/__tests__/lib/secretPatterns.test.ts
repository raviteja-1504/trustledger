import { analyzeFile } from "@/lib/scanner";

function indicatorIds(content: string, path = "internal/service.go") {
  const result = analyzeFile(path, content);
  return result.indicators.filter(i => i.id === "hardcoded-secret").map(i => i.detail);
}

describe("HashiCorp Vault token pattern", () => {
  it("does not flag Go method calls on a single-letter receiver named s", () => {
    // s.MethodName(...) is idiomatic Go (s *Server, s *Service) and is
    // syntactically identical in shape to a real Vault token (s.XXXXX...)
    // without the "not followed by (" exclusion.
    const content = `
package bsl

func (s *Server) saveCanonical(ginContext *gin.Context) {
	s.processRemoteCanonicalTransaction(bodyBytes, ginContext)
}

func (s *Server) sendMessage(ginContext *gin.Context) {
	if decodedPayload != nil {
		s.processLocalCanonicalTransaction(tlogId, decodedPayload, ginContext)
	}
}
`.repeat(1); // pad past the 50-char minimum content length gate
    const ids = indicatorIds(content.padEnd(60, "\n//"));
    expect(ids.some(d => d?.includes("Vault token"))).toBe(false);
  });

  it("still flags a real-shaped Vault token value", () => {
    const content = `
const vaultToken = "s.AbCdEfGhIjKlMnOpQrStUvWx";
`.padEnd(60, "\n//");
    const ids = indicatorIds(content, "src/config.ts");
    expect(ids.some(d => d?.includes("Vault token"))).toBe(true);
  });
});
