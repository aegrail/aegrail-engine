package llmparse

import (
	"net/http"
	"net/url"
	"testing"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", s, err)
	}
	return u
}

func TestRecognise(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		url  string
		want bool
	}{
		{"openai chat completions", "http://api.openai.com/v1/chat/completions", true},
		{"openai chat completions trailing slash", "http://api.openai.com/v1/chat/completions/", true},
		{"openai responses", "http://api.openai.com/v1/responses", true},
		{"anthropic messages", "http://api.anthropic.com/v1/messages", true},
		{"bedrock invoke", "http://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-5-sonnet/invoke", true},
		{"bedrock converse", "http://bedrock-runtime.us-west-2.amazonaws.com/model/anthropic.claude-3-5-sonnet/converse", true},
		{"vertex generateContent", "http://us-central1-aiplatform.googleapis.com/v1/projects/p/locations/us-central1/publishers/google/models/gemini-1.5-pro:generateContent", true},
		{"gemini AI studio", "http://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent", true},
		{"ollama generate localhost", "http://localhost:11434/api/generate", true},
		{"ollama chat localhost", "http://localhost:11434/api/chat", true},
		{"ollama in-cluster svc", "http://ollama.ai-models.svc.cluster.local:11434/api/generate", true},
		{"not an LLM url", "http://example.com/users", false},
		{"google.com", "http://www.google.com/", false},
		{"openai non-LLM path", "http://api.openai.com/v1/models", false},
		{"bedrock non-invoke path", "http://bedrock-runtime.us-east-1.amazonaws.com/model/x/get-model", false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := Recognise(mustURL(t, c.url)); got != c.want {
				t.Errorf("Recognise(%q) = %v, want %v", c.url, got, c.want)
			}
		})
	}
}

func TestParseResponse_OpenAIChat(t *testing.T) {
	t.Parallel()
	body := []byte(`{
		"id": "chatcmpl-xyz",
		"object": "chat.completion",
		"model": "gpt-4o-mini",
		"usage": {"prompt_tokens": 47, "completion_tokens": 88, "total_tokens": 135}
	}`)
	u := mustURL(t, "http://api.openai.com/v1/chat/completions")
	got := ParseResponse(u, body, nil)
	if !got.Recognised {
		t.Error("expected Recognised=true")
	}
	if got.Model != "gpt-4o-mini" {
		t.Errorf("Model: got %q, want gpt-4o-mini", got.Model)
	}
	if got.TokensIn != 47 || got.TokensOut != 88 {
		t.Errorf("tokens: in=%d out=%d, want 47/88", got.TokensIn, got.TokensOut)
	}
}

func TestParseResponse_OpenAIResponses(t *testing.T) {
	t.Parallel()
	body := []byte(`{
		"model": "gpt-4o",
		"usage": {"input_tokens": 120, "output_tokens": 240}
	}`)
	u := mustURL(t, "http://api.openai.com/v1/responses")
	got := ParseResponse(u, body, nil)
	if !got.Recognised {
		t.Error("expected Recognised=true")
	}
	if got.TokensIn != 120 || got.TokensOut != 240 {
		t.Errorf("tokens: in=%d out=%d, want 120/240", got.TokensIn, got.TokensOut)
	}
}

func TestParseResponse_AnthropicMessages(t *testing.T) {
	t.Parallel()
	body := []byte(`{
		"id": "msg_xyz",
		"model": "claude-3-5-sonnet-20240620",
		"role": "assistant",
		"content": [{"type":"text","text":"hi"}],
		"usage": {"input_tokens": 73, "output_tokens": 142,
		          "cache_creation_input_tokens": 12, "cache_read_input_tokens": 5}
	}`)
	u := mustURL(t, "http://api.anthropic.com/v1/messages")
	got := ParseResponse(u, body, nil)
	if !got.Recognised {
		t.Error("expected Recognised=true")
	}
	if got.Model != "claude-3-5-sonnet-20240620" {
		t.Errorf("Model: got %q, want claude-3-5-sonnet-20240620", got.Model)
	}
	if got.TokensIn != 73 || got.TokensOut != 142 {
		t.Errorf("tokens: in=%d out=%d, want 73/142", got.TokensIn, got.TokensOut)
	}
}

func TestParseResponse_BedrockHeaders(t *testing.T) {
	t.Parallel()
	headers := http.Header{}
	headers.Set("X-Amzn-Bedrock-Input-Token-Count", "108")
	headers.Set("X-Amzn-Bedrock-Output-Token-Count", "215")
	headers.Set("X-Amzn-Bedrock-Invocation-Latency", "843")
	body := []byte(`{"completion": "Hello..."}`) // body shape varies per model; ignored
	u := mustURL(t, "http://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-5-sonnet-20240620-v1:0/invoke")
	got := ParseResponse(u, body, headers)
	if !got.Recognised {
		t.Error("expected Recognised=true")
	}
	if got.Model != "anthropic.claude-3-5-sonnet-20240620-v1:0" {
		t.Errorf("Model: got %q, want anthropic.claude-3-5-sonnet-20240620-v1:0", got.Model)
	}
	if got.TokensIn != 108 || got.TokensOut != 215 {
		t.Errorf("tokens: in=%d out=%d, want 108/215", got.TokensIn, got.TokensOut)
	}
}

func TestParseResponse_VertexGenerateContent(t *testing.T) {
	t.Parallel()
	body := []byte(`{
		"candidates": [{"content":{"parts":[{"text":"hi"}]}}],
		"modelVersion": "gemini-1.5-pro-002",
		"usageMetadata": {
			"promptTokenCount": 91,
			"candidatesTokenCount": 188,
			"totalTokenCount": 279
		}
	}`)
	u := mustURL(t, "http://us-central1-aiplatform.googleapis.com/v1/projects/p/locations/us-central1/publishers/google/models/gemini-1.5-pro:generateContent")
	got := ParseResponse(u, body, nil)
	if !got.Recognised {
		t.Error("expected Recognised=true")
	}
	if got.Model != "gemini-1.5-pro-002" {
		t.Errorf("Model: got %q, want gemini-1.5-pro-002", got.Model)
	}
	if got.TokensIn != 91 || got.TokensOut != 188 {
		t.Errorf("tokens: in=%d out=%d, want 91/188", got.TokensIn, got.TokensOut)
	}
}

func TestParseResponse_Ollama(t *testing.T) {
	t.Parallel()
	body := []byte(`{
		"model": "llama3.2:3b",
		"created_at": "2026-05-16T...",
		"response": "Hello!",
		"done": true,
		"prompt_eval_count": 18,
		"eval_count": 32
	}`)
	u := mustURL(t, "http://localhost:11434/api/generate")
	got := ParseResponse(u, body, nil)
	if !got.Recognised {
		t.Error("expected Recognised=true")
	}
	if got.Model != "llama3.2:3b" {
		t.Errorf("Model: got %q, want llama3.2:3b", got.Model)
	}
	if got.TokensIn != 18 || got.TokensOut != 32 {
		t.Errorf("tokens: in=%d out=%d, want 18/32", got.TokensIn, got.TokensOut)
	}
}

func TestParseResponse_NonLLMURL(t *testing.T) {
	t.Parallel()
	u := mustURL(t, "http://example.com/")
	got := ParseResponse(u, []byte(`{"foo":"bar"}`), nil)
	if got.Recognised {
		t.Error("non-LLM URL should not be Recognised")
	}
	if got.TokensIn != 0 || got.TokensOut != 0 {
		t.Error("non-LLM URL should yield zero tokens")
	}
}

func TestParseResponse_MalformedBody(t *testing.T) {
	t.Parallel()
	u := mustURL(t, "http://api.openai.com/v1/chat/completions")
	got := ParseResponse(u, []byte(`not json at all`), nil)
	if !got.Recognised {
		t.Error("Recognised URL should still report Recognised even with bad body")
	}
	if got.TokensIn != 0 || got.TokensOut != 0 {
		t.Error("malformed body should yield zero tokens")
	}
}
