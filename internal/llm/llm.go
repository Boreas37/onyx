// Package llm provides a minimal, stdlib-only LLM abstraction for onyx.
//
// It is intentionally tiny: a single interface and two backends (OpenAI and
// Ollama) that use only net/http and encoding/json. No third-party SDK is
// imported, so the single-binary, stdlib-only invariant is preserved.
//
// Usage:
//
//   p, err := llm.NewProvider("openai", llm.Options{Model: "gpt-4o", APIKey: os.Getenv("OPENAI_API_KEY")})
//   out, err := p.Generate(ctx, systemPrompt, userPrompt)
package llm

import (
	"context"
	"fmt"
	"strings"
)

// Provider is the LLM backend used by pocgen and report enrichment.
type Provider interface {
	Generate(ctx context.Context, systemPrompt, userPrompt string) (string, error)
	Name() string
}

// Options tunes provider construction. Zero values fall back to defaults.
type Options struct {
	Provider string // "openai" | "ollama" | "anthropic" (anthropic uses OpenAI-compatible path for now)
	Model    string
	APIKey   string // for openai/anthropic; ignored for ollama
	Endpoint string // override base URL (e.g. http://localhost:11434 for ollama)
	Timeout  int    // seconds, default 60
}

// NewProvider returns a Provider for name, using opts. Unknown names return
// an error. APIKey may be empty for ollama.
func NewProvider(name string, opts Options) (Provider, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		name = "openai"
	}
	switch name {
	case "openai", "gpt", "gpt-4o", "o1":
		return NewOpenAI(opts)
	case "ollama", "local", "llama":
		return NewOllama(opts)
	case "anthropic", "claude":
		return NewAnthropic(opts)
	default:
		return nil, fmt.Errorf("unknown llm provider %q (use openai, ollama or anthropic)", name)
	}
}
