package llmparse

import (
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
		{"ollama generate localhost", "http://localhost:11434/api/generate", true},
		{"ollama chat localhost", "http://localhost:11434/api/chat", true},
		{"ollama in-cluster svc", "http://ollama.ai-models.svc.cluster.local:11434/api/generate", true},
		{"not an LLM url", "http://example.com/users", false},
		{"google.com", "http://www.google.com/", false},
		{"openai non-LLM path", "http://api.openai.com/v1/models", false},
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
	got := ParseResponse(u, body)
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
	got := ParseResponse(u, body)
	if !got.Recognised {
		t.Error("expected Recognised=true")
	}
	if got.TokensIn != 120 || got.TokensOut != 240 {
		t.Errorf("tokens: in=%d out=%d, want 120/240", got.TokensIn, got.TokensOut)
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
	got := ParseResponse(u, body)
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
	got := ParseResponse(u, []byte(`{"foo":"bar"}`))
	if got.Recognised {
		t.Error("non-LLM URL should not be Recognised")
	}
	if got.TokensIn != 0 || got.TokensOut != 0 {
		t.Error("non-LLM URL should yield zero tokens")
	}
}

func TestParseResponse_MalformedBody(t *testing.T) {
	t.Parallel()
	// Recognised URL with garbage body — still Recognised but zero tokens.
	u := mustURL(t, "http://api.openai.com/v1/chat/completions")
	got := ParseResponse(u, []byte(`not json at all`))
	if !got.Recognised {
		t.Error("Recognised URL should still report Recognised even with bad body")
	}
	if got.TokensIn != 0 || got.TokensOut != 0 {
		t.Error("malformed body should yield zero tokens")
	}
}
