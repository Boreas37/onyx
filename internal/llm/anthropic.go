package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Anthropic implements Provider via the Anthropic Messages API
// (https://api.anthropic.com/v1/messages).
type Anthropic struct {
	model    string
	apiKey   string
	endpoint string
	client   *http.Client
}

// NewAnthropic returns an Anthropic provider. Model defaults to
// claude-3-5-sonnet-20241022, endpoint to https://api.anthropic.com/v1/messages.
func NewAnthropic(opts Options) (*Anthropic, error) {
	model := opts.Model
	if model == "" {
		model = "claude-3-5-sonnet-20241022"
	}
	endpoint := opts.Endpoint
	if endpoint == "" {
		endpoint = "https://api.anthropic.com/v1/messages"
	}
	if opts.APIKey == "" {
		return nil, fmt.Errorf("anthropic provider requires API key (set ANTHROPIC_API_KEY or --llm-api-key)")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 60
	}
	return &Anthropic{
		model:    model,
		apiKey:   opts.APIKey,
		endpoint: endpoint,
		client:   &http.Client{Timeout: time.Duration(timeout) * time.Second},
	}, nil
}

// Name returns the provider name.
func (a *Anthropic) Name() string { return "anthropic" }

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Generate sends system+user prompts to Anthropic and returns the text.
func (a *Anthropic) Generate(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	reqBody := anthropicRequest{
		Model:     a.model,
		MaxTokens: 4096,
		System:    systemPrompt,
		Messages:  []anthropicMessage{{Role: "user", Content: userPrompt}},
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", a.endpoint, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", a.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("anthropic request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("anthropic HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out anthropicResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("anthropic decode: %w", err)
	}
	if out.Error != nil {
		return "", fmt.Errorf("anthropic error: %s", out.Error.Message)
	}
	if len(out.Content) == 0 {
		return "", fmt.Errorf("anthropic: no content in response")
	}
	var b strings.Builder
	for _, c := range out.Content {
		b.WriteString(c.Text)
		b.WriteString("\n")
	}
	return strings.TrimSpace(b.String()), nil
}
