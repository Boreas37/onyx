package report

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/Boreas37/onyx/internal/scanner"
)

// cdxDoc mirrors the subset of the CycloneDX document the tests assert on.
// Components stay generic maps so tests can verify that optional keys
// (e.g. "version" for unknown versions) are truly absent from the JSON.
type cdxDoc struct {
	BOMFormat    string `json:"bomFormat"`
	SpecVersion  string `json:"specVersion"`
	SerialNumber string `json:"serialNumber"`
	Version      int    `json:"version"`
	Metadata     struct {
		Tools struct {
			Components []struct {
				Type    string `json:"type"`
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"components"`
		} `json:"tools"`
		Component struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"component"`
	} `json:"metadata"`
	Components []map[string]any `json:"components"`
}

var uuidShape = regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestPrintCycloneDXDocument(t *testing.T) {
	res := &scanner.Result{
		Target: "https://example.com",
		Detected: []scanner.Detected{
			{Slug: "zebra", Name: "Zebra Plugin", Type: "plugin", Version: "1.2.3"},
			{Slug: "alpha", Name: "Alpha Theme", Type: "theme", Version: "unknown"},
			{Slug: "alpha", Name: "Alpha Plugin", Type: "plugin", Version: "2.0"},
		},
	}
	out := captureStdout(t, func() { PrintCycloneDX("1.2.3-testing", res) })

	var doc cdxDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}

	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.5" {
		t.Errorf("bomFormat/specVersion = %q/%q, want CycloneDX/1.5", doc.BOMFormat, doc.SpecVersion)
	}
	if doc.Version != 1 {
		t.Errorf("version = %d, want 1", doc.Version)
	}
	if !uuidShape.MatchString(doc.SerialNumber) {
		t.Errorf("serialNumber = %q, want urn:uuid:<rfc4122 v4>", doc.SerialNumber)
	}
	if len(doc.Metadata.Tools.Components) != 1 ||
		doc.Metadata.Tools.Components[0].Name != "onyx" ||
		doc.Metadata.Tools.Components[0].Version != "1.2.3-testing" {
		t.Errorf("metadata.tools = %+v, want single onx tool component", doc.Metadata.Tools.Components)
	}
	if doc.Metadata.Component.Type != "application" || doc.Metadata.Component.Name != "https://example.com" {
		t.Errorf("metadata.component = %+v, want application targeting res.Target", doc.Metadata.Component)
	}

	if len(doc.Components) != 3 {
		t.Fatalf("got %d components, want 3 (full doc: %s)", len(doc.Components), out)
	}

	// Order: slug asc then type asc — alpha/plugin < alpha/theme < zebra.
	wantOrder := []struct{ ref, name string }{
		{"pkg:wordpress/plugin/alpha@2.0", "alpha"},
		{"pkg:wordpress/theme/alpha", "alpha"},
		{"pkg:wordpress/plugin/zebra@1.2.3", "zebra"},
	}
	for i, want := range wantOrder {
		c := doc.Components[i]
		name, _ := c["name"].(string)
		ref, _ := c["bom-ref"].(string)
		typ, _ := c["type"].(string)
		if name != want.name || ref != want.ref {
			t.Errorf("component[%d] = name %q ref %q, want name %q ref %q", i, name, ref, want.name, want.ref)
		}
		if typ != "application" {
			t.Errorf("component[%d].type = %q, want application", i, typ)
		}
		props, ok := c["properties"].([]any)
		if !ok || len(props) != 1 {
			t.Fatalf("component[%d] properties missing: %v", i, c["properties"])
		}
		p := props[0].(map[string]any)
		if p["name"] != "onyx:type" || p["value"] == "" {
			t.Errorf("component[%d] property = %v, want onyx:type with plugin|theme value", i, p)
		}
	}

	// Unknown version must be omitted entirely, not emitted as "" or "unknown".
	if _, present := doc.Components[1]["version"]; present {
		t.Errorf("component[1] (unknown version) must omit the version key, got %q", doc.Components[1]["version"])
	}
	props := doc.Components[1]["properties"].([]any)
	if got := props[0].(map[string]any)["value"]; got != "theme" {
		t.Errorf("component[1] onyx:type = %v, want theme", got)
	}
	if v, _ := doc.Components[0]["version"].(string); v != "2.0" {
		t.Errorf("component[0].version = %v, want 2.0", doc.Components[0]["version"])
	}
}

func TestPrintCycloneDXSanitizesHostileInput(t *testing.T) {
	res := &scanner.Result{
		Target: "https://evil.example",
		Detected: []scanner.Detected{{
			Slug:    "\x1b[31mplug\x01in\n",
			Type:    "PLUGIN",
			Version: strings.Repeat("9", 100),
		}},
	}
	out := captureStdout(t, func() { PrintCycloneDX("dev", res) })

	var doc cdxDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if len(doc.Components) != 1 {
		t.Fatalf("got %d components, want 1", len(doc.Components))
	}
	c := doc.Components[0]
	name, _ := c["name"].(string)
	if strings.ContainsAny(name, "\x1b\x01\n\r") {
		t.Errorf("control characters survived into component name %q", name)
	}
	if name != "[31mplugin" {
		t.Errorf("component name = %q, want %q after stripping control chars", name, "[31mplugin")
	}
	version, _ := c["version"].(string)
	if len(version) != 64 {
		t.Errorf("version length = %d, want capped at 64", len(version))
	}
	ref, _ := c["bom-ref"].(string)
	if ref != "pkg:wordpress/plugin/[31mplugin@"+strings.Repeat("9", 64) {
		t.Errorf("bom-ref = %q, want sanitized lowercased-type ref", ref)
	}
}

// TestWriteCycloneDXRemediationProperty verifies a finding's remediation is
// attached to the matching detected component as an onyx:remediation
// property, and components without matching findings keep only their
// onyx:type property.
func TestWriteCycloneDXRemediationProperty(t *testing.T) {
	res := &scanner.Result{
		Target: "https://example.com",
		Detected: []scanner.Detected{
			{Slug: "alpha", Name: "Alpha Plugin", Type: "plugin", Version: "2.0"},
			{Slug: "zebra", Name: "Zebra Plugin", Type: "plugin", Version: "1.0"},
		},
		Findings: []scanner.Finding{
			{
				Slug: "alpha", Type: "plugin", InstalledVersion: "2.0",
				Vulnerabilities: []scanner.Vulnerability{
					{CVE: "CVE-2026-0001", Rating: "high", Title: "T", Remediation: "Update to 2.1"},
					{CVE: "CVE-2026-0002", Rating: "low", Title: "U"},
				},
			},
			{
				Slug: "beta", Type: "plugin", InstalledVersion: "1.0",
				Vulnerabilities: []scanner.Vulnerability{
					{CVE: "CVE-2026-0003", Rating: "medium", Title: "V",
						Remediation: "remediation for a component that is not detected"},
				},
			},
		},
	}
	var buf bytes.Buffer
	writeCycloneDX(&buf, "dev", res)
	var doc cdxDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("cyclonedx output is not valid JSON: %v\n%s", err, buf.String())
	}
	propsByRef := make(map[string][]map[string]any)
	for _, c := range doc.Components {
		ref, _ := c["bom-ref"].(string)
		raw, _ := c["properties"].([]any)
		var props []map[string]any
		for _, p := range raw {
			props = append(props, p.(map[string]any))
		}
		propsByRef[ref] = props
	}

	alpha := propsByRef["pkg:wordpress/plugin/alpha@2.0"]
	if len(alpha) != 2 {
		t.Fatalf("alpha properties = %v, want onyx:type + onyx:remediation", alpha)
	}
	var got string
	for _, p := range alpha {
		if p["name"] == "onyx:remediation" {
			got, _ = p["value"].(string)
		}
	}
	if got != "Update to 2.1" {
		t.Errorf("alpha onyx:remediation = %q, want %q", got, "Update to 2.1")
	}

	zebra := propsByRef["pkg:wordpress/plugin/zebra@1.0"]
	if len(zebra) != 1 || zebra[0]["name"] != "onyx:type" {
		t.Errorf("zebra (no matching finding) must keep only onyx:type, got %v", zebra)
	}
}

// TestWriteCycloneDXActiveInstalls verifies a detected component's active
// install count is attached as an onyx:active-installs property, and that
// components without a known count (0) keep only their onyx:type property.
func TestWriteCycloneDXActiveInstalls(t *testing.T) {
	res := &scanner.Result{
		Target: "https://example.com",
		Detected: []scanner.Detected{
			{Slug: "alpha", Name: "Alpha Plugin", Type: "plugin", Version: "2.0", ActiveInstalls: 4000000},
			{Slug: "zebra", Name: "Zebra Plugin", Type: "plugin", Version: "1.0"},
		},
	}
	var buf bytes.Buffer
	writeCycloneDX(&buf, "dev", res)
	var doc cdxDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("cyclonedx output is not valid JSON: %v\n%s", err, buf.String())
	}
	propsByRef := make(map[string][]map[string]any)
	for _, c := range doc.Components {
		ref, _ := c["bom-ref"].(string)
		raw, _ := c["properties"].([]any)
		var props []map[string]any
		for _, p := range raw {
			props = append(props, p.(map[string]any))
		}
		propsByRef[ref] = props
	}

	alpha := propsByRef["pkg:wordpress/plugin/alpha@2.0"]
	if len(alpha) != 2 {
		t.Fatalf("alpha properties = %v, want onyx:type + onyx:active-installs", alpha)
	}
	var got string
	for _, p := range alpha {
		if p["name"] == "onyx:active-installs" {
			got, _ = p["value"].(string)
		}
	}
	if got != "4000000" {
		t.Errorf("alpha onyx:active-installs = %q, want %q", got, "4000000")
	}

	zebra := propsByRef["pkg:wordpress/plugin/zebra@1.0"]
	if len(zebra) != 1 || zebra[0]["name"] != "onyx:type" {
		t.Errorf("zebra (unknown install count) must keep only onyx:type, got %v", zebra)
	}
}

func TestUUIDV4UniqueAndShaped(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := uuidV4()
		if !uuidShape.MatchString("urn:uuid:" + id) {
			t.Fatalf("uuidV4() = %q, not a valid v4 UUID", id)
		}
		if seen[id] {
			t.Fatalf("uuidV4() repeated %q across calls", id)
		}
		seen[id] = true
	}
}
