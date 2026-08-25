package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Boreas37/onyx/internal/llm"
)

// Analysis is the result of an LLM-backed PoC review.
type Analysis struct {
	Risk    string   `json:"risk"`    // low | high
	Reasons []string `json:"reasons"` // why
	Summary string   `json:"summary"` // one-line human summary
}

const analyzeSystemPrompt = `You are a sandbox security reviewer for WordPress PoC code.

Task: Review the provided PoC code for malicious behavior that would harm the tester's own lab.

Flag as HIGH risk only if the code:
- executes destructive commands (rm -rf, mkfs, dd if=)
- opens reverse shells (nc -e, bash -i, socat exec)
- exfiltrates data to external hosts (requests to non-localhost, ftp, upload)
- obfuscates payloads (large base64 decode + exec)
- modifies host permissions broadly (chmod 777 /)

Do NOT flag normal PoC behavior: HTTP requests to the target URL (127.0.0.1/localhost/target), reading readme, printing [VULN]/[SAFE].

Respond ONLY with JSON: {"risk":"low"|"high","reasons":["..."],"summary":"..."}`

// AnalyzeWithLLM asks the LLM to review code for malicious patterns.
// It returns RiskLow on any error (soft fail) so the scan is not blocked
// by a missing or rate-limited LLM.
func AnalyzeWithLLM(ctx context.Context, provider llm.Provider, code string) (Analysis, error) {
	if provider == nil {
		return Analysis{Risk: RiskLow, Summary: "no LLM provider — static check only"}, nil
	}
	trimmed := code
	if len(trimmed) > 8000 {
		trimmed = trimmed[:8000] + "\n...[truncated]"
	}
	userPrompt := fmt.Sprintf("Review this PoC code (first 8000 chars):\n```\n%s\n```\n\nRespond with JSON only.", trimmed)
	out, err := provider.Generate(ctx, analyzeSystemPrompt, userPrompt)
	if err != nil {
		// Soft fail: return low risk with the error as summary, caller will
		// combine with static check.
		return Analysis{Risk: RiskLow, Summary: fmt.Sprintf("llm unavailable: %v", err)}, err
	}
	// The LLM may wrap JSON in markdown fences; extract the first { ... }.
	jsonStr := extractJSON(out)
	var a Analysis
	if err := json.Unmarshal([]byte(jsonStr), &a); err != nil {
		// If parsing fails, treat the whole output as summary with low risk.
		return Analysis{Risk: RiskLow, Summary: strings.TrimSpace(out)}, nil
	}
	a.Risk = strings.ToLower(strings.TrimSpace(a.Risk))
	if a.Risk != RiskHigh {
		a.Risk = RiskLow
	}
	return a, nil
}

// extractJSON returns the first {...} block in s, or s itself if none found.
func extractJSON(s string) string {
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start >= 0 && end > start {
		return s[start : end+1]
	}
	return s
}

// CombinedRisk merges static and LLM risks: high if either is high.
func CombinedRisk(staticRisk string, staticReasons []string, llmAnalysis Analysis) (string, []string, string) {
	if staticRisk == RiskHigh || llmAnalysis.Risk == RiskHigh {
		reasons := append([]string{}, staticReasons...)
		reasons = append(reasons, llmAnalysis.Reasons...)
		// Deduplicate a bit, cap.
		seen := make(map[string]bool)
		var uniq []string
		for _, r := range reasons {
			if !seen[r] {
				seen[r] = true
				uniq = append(uniq, r)
			}
			if len(uniq) >= 6 {
				break
			}
		}
		summary := llmAnalysis.Summary
		if summary == "" && len(staticReasons) > 0 {
			summary = "static: " + strings.Join(staticReasons, "; ")
		}
		return RiskHigh, uniq, summary
	}
	return RiskLow, nil, llmAnalysis.Summary
}
