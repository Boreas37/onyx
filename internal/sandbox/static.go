// Package sandbox provides static and LLM-based analysis for PoC code.
//
// It runs before and after pocgen's LLM adaptation to flag malicious
// patterns (reverse shells, destructive commands, exfiltration) that
// sometimes appear in public PoC repositories. Static checks are
// deterministic and stdlib-only; LLM analysis is optional and soft-fails.
package sandbox

import (
	"regexp"
	"strings"
)

// Risk levels returned by the analyzers.
const (
	RiskLow  = "low"
	RiskHigh = "high"
)

// staticPattern is one deterministic malicious pattern.
type staticPattern struct {
	re     *regexp.Regexp
	reason string
}

var staticPatterns = []staticPattern{
	{regexp.MustCompile(`(?i)\brm\s+-rf\b`), "destructive rm -rf"},
	{regexp.MustCompile(`(?i)\bmkfs\b|\bdd\s+if=`), "destructive disk command"},
	{regexp.MustCompile(`(?i)\bnc\s+.*-e\b|\bncat\s+.*-e\b|\bsocat\b.*exec`), "reverse shell (nc -e / socat exec)"},
	{regexp.MustCompile(`(?i)__import__\s*\(\s*['"]os['"]\s*\)`), "dynamic os import"},
	{regexp.MustCompile(`(?i)\bos\.system\s*\(|\bos\.popen\s*\(|\bsubprocess\.(Popen|call|run)\s*\(`), "os command execution"},
	{regexp.MustCompile(`(?i)\beval\s*\(|\bexec\s*\(|\bcompile\s*\(.*code`), "dynamic code execution (eval/exec)"},
	{regexp.MustCompile(`(?i)\bsocket\.(socket|connect|create_connection)\s*\(`), "raw socket"},
	{regexp.MustCompile(`(?i)base64\.b64decode|base64\.decode`), "obfuscated base64 decode (possible payload hiding)"},
	{regexp.MustCompile(`(?i)chmod\s+\+x|chmod\s+777`), "suspicious chmod +x/777"},
	{regexp.MustCompile(`(?i)curl\s+.*\|\s*sh|wget\s+.*\|\s*sh`), "curl|sh pipe (remote code execution)"},
}

// StaticCheck scans code for deterministic malicious patterns. It returns
// RiskHigh when any pattern matches, otherwise RiskLow. Reasons are the
// matched pattern descriptions, capped to avoid spam.
func StaticCheck(code string) (string, []string) {
	var reasons []string
	lower := strings.ToLower(code)
	_ = lower
	for _, p := range staticPatterns {
		if p.re.MatchString(code) {
			reasons = append(reasons, p.reason)
			if len(reasons) >= 5 {
				break
			}
		}
	}
	if len(reasons) > 0 {
		return RiskHigh, reasons
	}
	return RiskLow, nil
}
