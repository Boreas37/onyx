package report

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Boreas37/onyx/internal/sanitize"
	"github.com/Boreas37/onyx/internal/scanner"
)

// Length caps for target-controlled strings embedded in the BOM.
const (
	cdxMaxName        = 200
	cdxMaxVersion     = 64
	cdxMaxRemediation = 500
)

// cdxComponent is one entry of the CycloneDX components array.
type cdxComponent struct {
	Type       string        `json:"type"`
	BomRef     string        `json:"bom-ref,omitempty"`
	Name       string        `json:"name"`
	Version    string        `json:"version,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

// cdxProperty is a name/value pair attached to a component.
type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// cdxBOM is the top-level CycloneDX 1.5 document.
type cdxBOM struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     cdxMetadata    `json:"metadata"`
	Components   []cdxComponent `json:"components"`
}

// cdxMetadata describes the tool that produced the BOM and its subject.
type cdxMetadata struct {
	Timestamp string       `json:"timestamp"`
	Tools     cdxToolList  `json:"tools"`
	Component cdxComponent `json:"component"`
}

// cdxToolList uses the CycloneDX 1.5 object form of tools.
type cdxToolList struct {
	Components []cdxComponent `json:"components"`
}

// uuidV4 returns a random RFC 4122 version-4 UUID string.
func uuidV4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// uuidV4Fn is the serializer's UUID source; swapped by tests for
// deterministic golden output. Public behavior is unchanged.
var uuidV4Fn = uuidV4

// cdxRef builds the sanitized "pkg:wordpress/<type>/<slug>@<version>"
// bom-ref; the @version suffix is dropped for unknown versions.
func cdxRef(kind, slug, version string) string {
	ref := "pkg:wordpress/" + strings.ToLower(sanitize.Text(kind, cdxMaxName)) + "/" + slug
	if version != "" && version != "unknown" {
		ref += "@" + version
	}
	return ref
}

// componentRemediation returns the first non-empty remediation recorded for
// the component (slug, type). The BOM is keyed by detected component while
// remediation lives on vulnerabilities, so the closest component-level
// equivalent is the first matching finding's guidance; empty when the
// component has none.
func componentRemediation(res *scanner.Result, slug, typ string) string {
	for i := range res.Findings {
		f := &res.Findings[i]
		if f.Slug != slug || f.Type != typ {
			continue
		}
		for _, v := range f.Vulnerabilities {
			if v.Remediation != "" {
				return v.Remediation
			}
		}
	}
	return ""
}

// writeCycloneDX writes res as a CycloneDX 1.5 JSON BOM to w: one
// application component per detected plugin/theme, ordered by slug then
// type, with onyx:type properties. A component's active install count is
// attached as an onyx:active-installs property when known (0 or unset
// components carry only onyx:type). Target-controlled strings are stripped
// of control characters and length-capped before embedding so a hostile
// target cannot corrupt the document.
func writeCycloneDX(w io.Writer, toolVersion string, res *scanner.Result) {
	bom := cdxBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: "urn:uuid:" + uuidV4Fn(),
		Version:      1,
		Components:   []cdxComponent{},
		Metadata: cdxMetadata{
			Timestamp: now().UTC().Format(time.RFC3339),
			Tools: cdxToolList{Components: []cdxComponent{{
				Type:    "application",
				Name:    "onyx",
				Version: sanitize.Text(toolVersion, cdxMaxVersion),
			}}},
			Component: cdxComponent{
				Type:   "application",
				Name:   sanitize.Text(res.Target, cdxMaxName),
				BomRef: sanitize.Text(res.Target, cdxMaxName),
			},
		},
	}

	comps := make([]scanner.Detected, len(res.Detected))
	copy(comps, res.Detected)
	sort.SliceStable(comps, func(a, b int) bool {
		if comps[a].Slug != comps[b].Slug {
			return comps[a].Slug < comps[b].Slug
		}
		return comps[a].Type < comps[b].Type
	})
	for _, d := range comps {
		slug := sanitize.Text(d.Slug, cdxMaxName)
		version := sanitize.Text(d.Version, cdxMaxVersion)
		known := version != "" && version != "unknown"
		if !known {
			version = ""
		}
		c := cdxComponent{
			Type:    "application",
			Name:    slug,
			Version: version,
			Properties: []cdxProperty{{
				Name:  "onyx:type",
				Value: strings.ToLower(sanitize.Text(d.Type, cdxMaxName)),
			}},
		}
		if d.ActiveInstalls > 0 {
			c.Properties = append(c.Properties, cdxProperty{
				Name:  "onyx:active-installs",
				Value: strconv.Itoa(d.ActiveInstalls),
			})
		}
		if rem := componentRemediation(res, d.Slug, d.Type); rem != "" {
			c.Properties = append(c.Properties, cdxProperty{
				Name:  "onyx:remediation",
				Value: sanitize.Text(rem, cdxMaxRemediation),
			})
		}
		c.BomRef = cdxRef(d.Type, slug, version)
		bom.Components = append(bom.Components, c)
	}

	out, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cyclonedx output:", err)
		return
	}
	fmt.Fprintln(w, string(out))
}

// WriteCycloneDX writes res as a CycloneDX 1.5 JSON BOM to w (used by
// --output).
func WriteCycloneDX(w io.Writer, toolVersion string, res *scanner.Result) {
	writeCycloneDX(w, toolVersion, res)
}

// PrintCycloneDX writes res as a CycloneDX 1.5 JSON BOM to stdout.
func PrintCycloneDX(toolVersion string, res *scanner.Result) {
	writeCycloneDX(os.Stdout, toolVersion, res)
}
