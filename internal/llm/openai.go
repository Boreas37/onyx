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

// OpenAI implements Provider via the OpenAI Chat Completions API
// (https://api.openai.com/v1/chat/completions). It also works with
// OpenAI-compatible endpoints when Endpoint is overridden.
type OpenAI struct {
	model    string
	apiKey   string
	endpoint string
	client   *http.Client
}

// NewOpenAI returns an OpenAI provider. Model defaults to gpt-4o, endpoint
// to https://api.openai.com, timeout to 60s.
func NewOpenAI(opts Options) (*OpenAI, error) {
	model := opts.Model
	if model == "" {
		model = "gpt-4o"
	}
	endpoint := opts.Endpoint
	if endpoint == "" {
		endpoint = "https://api.openai.com/v1/chat/completions"
	}
	if opts.APIKey == "" {
		return nil, fmt.Errorf("openai provider requires API key (set OPENAI_API_KEY or --llm-api-key)")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 60
	}
	return &OpenAI{
		model:    model,
		apiKey:   opts.APIKey,
		endpoint: endpoint,
		client:   &http.Client{Timeout: time.Duration(timeout) * time.Second},
	}, nil
}

// Name returns the provider name.
func (o *OpenAI) Name() string { return "openai" }

type openAIRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
	Temp     float64         `json:"temperature,omitempty"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

// Generate sends system+user prompts to the OpenAI endpoint and returns the
// assistant's content. Non-200 is returned as an error.
func (o *OpenAI) Generate(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	reqBody := openAIRequest{
		Model: o.model,
		Messages: []openAIMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Temp: 0.2,
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
	req.Header.Set("Authorization", "Bearer "+o.apiKey)
	resp, err := o.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("openai request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out openAIResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("openai decode: %w", err)
	}
	if out.Error != nil {
		return "", fmt.Errorf("openai error: %s", out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("openai: no choices in response")
	}
	return strings.TrimSpace(out.Choices[0].Message.Content), nil
}
