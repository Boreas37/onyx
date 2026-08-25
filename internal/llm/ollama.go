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

// Ollama implements Provider via the local Ollama API
// (http://localhost:11434/api/chat). It requires no API key.
type Ollama struct {
	model    string
	endpoint string
	client   *http.Client
}

// NewOllama returns an Ollama provider. Model defaults to llama3.2,
// endpoint to http://localhost:11434/api/chat, timeout to 120s (local
// inference is slower).
func NewOllama(opts Options) (*Ollama, error) {
	model := opts.Model
	if model == "" {
		model = "llama3.2"
	}
	endpoint := opts.Endpoint
	if endpoint == "" {
		endpoint = "http://localhost:11434/api/chat"
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 120
	}
	return &Ollama{
		model:    model,
		endpoint: endpoint,
		client:   &http.Client{Timeout: time.Duration(timeout) * time.Second},
	}, nil
}

// Name returns the provider name.
func (o *Ollama) Name() string { return "ollama" }

type ollamaRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaResponse struct {
	Message struct {
		Content string `json:"content"`
	} `json:"message"`
	Error string `json:"error,omitempty"`
}

// Generate sends system+user prompts to the Ollama endpoint and returns the
// assistant's content. Ollama's /api/chat returns a single JSON object when
// stream=false.
func (o *Ollama) Generate(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	reqBody := ollamaRequest{
		Model: o.model,
		Messages: []ollamaMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Stream: false,
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", o.endpoint, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out ollamaResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("ollama decode: %w", err)
	}
	if out.Error != "" {
		return "", fmt.Errorf("ollama error: %s", out.Error)
	}
	return strings.TrimSpace(out.Message.Content), nil
}
