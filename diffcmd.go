package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/Boreas37/onyx/internal/scanner"
)

// runExampleConfig prints a fully-commented JSON config template to
// stdout, mirroring every key applyConfig understands. Useful as a
// starting point for --config and for the auto-discovered defaults file.
func runExampleConfig(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: onyx example-config")
		return 2
	}
	tpl := `{
  // onyx scan defaults — CLI flags always win over these values.
  // Save as ~/.config/onyx/scan.json (or ./onyx.json) to apply
  // automatically to every scan.
  "url": "https://example.com",       // optional default target
  "threads": 5,
  "rate_limit": 0,                    // requests/second, 0 = unlimited
  "detection_mode": "mixed",          // passive | aggressive | mixed
  "format": "table",                  // table | json | jsonl | sarif | csv | cyclonedx | md | html | junit
  "min_severity": "low",              // critical | high | medium | low
  "enumerate": "pt",                  // p plugins, t themes, u users, m media
  "max_requests": 500,
  "crawl_pages": 0,
  "stealth": false,
  "random_user_agent": false,
  "no_brute": false,
  "fail_on": "",                      // CI gate: critical | high | medium | low
  "strict_wp": false,
  "per_host_rate_limit": 0
}
`
	fmt.Println(tpl)
	return 0
}

// runDiff compares two saved scan results (onyx scan --format json
// output) and reports vulnerability-level differences between them:
// which (slug, cve) pairs appeared, disappeared, or changed version.
// Exit codes: 0 identical, 1 differs, 2 usage/parse error.
func runDiff(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: onyx diff A.json B.json")
		return 2
	}
	a, err := loadScanResult(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "diff:", err)
		return 2
	}
	b, err := loadScanResult(args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "diff:", err)
		return 2
	}
	type key struct {
		slug, typ, cve string
	}
	index := func(r *scanner.Result) map[key]string {
		m := make(map[key]string)
		for i := range r.Findings {
			f := &r.Findings[i]
			for _, v := range f.Vulnerabilities {
				cve := v.CVE
				if cve == "" {
					cve = v.ID
				}
				m[key{f.Slug, f.Type, cve}] = f.InstalledVersion
			}
		}
		return m
	}
	ma, mb := index(a), index(b)
	var added, removed, changed, unchanged []string
	for k, ver := range mb {
		av, ok := ma[k]
		if !ok {
			added = append(added, fmt.Sprintf("%s/%s %s", k.typ, k.slug, k.cve))
		} else if av != ver {
			changed = append(changed, fmt.Sprintf("%s/%s %s (%s -> %s)", k.typ, k.slug, k.cve, av, ver))
		} else {
			unchanged = append(unchanged, k.slug+"/"+k.cve)
		}
	}
	for k := range ma {
		if _, ok := mb[k]; !ok {
			removed = append(removed, fmt.Sprintf("%s/%s %s", k.typ, k.slug, k.cve))
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)
	sort.Strings(unchanged)

	fmt.Printf("onyx diff %s %s\n", args[0], args[1])
	fmt.Printf("  added:    %d\n", len(added))
	fmt.Printf("  removed:  %d\n", len(removed))
	fmt.Printf("  changed:  %d\n", len(changed))
	fmt.Printf("  unchanged:%d\n", len(unchanged))
	for _, l := range added {
		fmt.Printf("  + %s\n", l)
	}
	for _, l := range removed {
		fmt.Printf("  - %s\n", l)
	}
	for _, l := range changed {
		fmt.Printf("  ~ %s\n", l)
	}
	if len(added)+len(removed)+len(changed) == 0 {
		fmt.Println("results are identical")
		return 0
	}
	return 1
}

// loadScanResult reads a saved onyx scan JSON output.
func loadScanResult(path string) (*scanner.Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r scanner.Result
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &r, nil
}
