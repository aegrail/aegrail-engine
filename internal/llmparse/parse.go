// Package llmparse recognises common LLM-provider HTTP request URL
// shapes and extracts token usage from their response bodies. The
// engine uses this to enforce token budgets at the network layer
// for callers who never imported the aegrail SDK.
//
// v0.3.0 ships parsers for:
//
//   - Ollama generate    POST /api/generate    {prompt_eval_count, eval_count}
//   - Ollama chat        POST /api/chat        {prompt_eval_count, eval_count}
//   - OpenAI Chat Comp.  POST /v1/chat/completions  {usage.prompt_tokens,
//                                                    usage.completion_tokens}
//   - OpenAI Responses   POST /v1/responses    {usage.input_tokens,
//                                               usage.output_tokens}
//
// Note: HTTPS upstreams traverse the proxy as CONNECT tunnels, so
// their bodies are opaque to this code. Token parsing only fires
// on plain-HTTP forwards. Operators who terminate TLS upstream of
// the engine (e.g. via an in-cluster TLS-terminating reverse proxy)
// see full coverage; for the standard "agent talks to api.openai.com
// directly over HTTPS" pattern, this layer doesn't activate. The
// v0.4.x MITM mode addresses that case explicitly.

package llmparse

import (
	"encoding/json"
	"net/url"
	"strings"
)

// Usage is the extracted, normalized token usage from any
// supported LLM response shape.
type Usage struct {
	Model      string
	TokensIn   int
	TokensOut  int
	Recognised bool // true if the request matched a known LLM URL shape
}

// Recognise reports whether the given request URL targets a known
// LLM endpoint. Useful as a pre-check before reading the response
// body — recognising early lets the proxy skip body buffering for
// non-LLM traffic.
func Recognise(u *url.URL) bool {
	host, path := u.Hostname(), strings.TrimRight(u.Path, "/")
	switch {
	case host == "api.openai.com" && strings.HasSuffix(path, "/v1/chat/completions"),
		host == "api.openai.com" && strings.HasSuffix(path, "/v1/responses"):
		return true
	case strings.HasSuffix(path, "/api/generate"),
		strings.HasSuffix(path, "/api/chat"):
		// Ollama (any host — usually localhost / in-cluster service)
		return true
	}
	return false
}

// ParseResponse parses a JSON LLM response body and returns the
// extracted Usage. Tolerant of unknown shapes — returns a zero
// Usage with Recognised=false rather than erroring, so the caller
// can decide whether to budget-enforce or just pass through.
func ParseResponse(reqURL *url.URL, body []byte) Usage {
	if !Recognise(reqURL) {
		return Usage{}
	}
	host, path := reqURL.Hostname(), strings.TrimRight(reqURL.Path, "/")
	switch {
	case host == "api.openai.com" && strings.HasSuffix(path, "/v1/chat/completions"):
		return parseOpenAIChat(body)
	case host == "api.openai.com" && strings.HasSuffix(path, "/v1/responses"):
		return parseOpenAIResponses(body)
	case strings.HasSuffix(path, "/api/generate"),
		strings.HasSuffix(path, "/api/chat"):
		return parseOllama(body)
	}
	return Usage{}
}

// -- per-provider parsers ----------------------------------------

type openaiChatResp struct {
	Model string `json:"model"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func parseOpenAIChat(body []byte) Usage {
	var r openaiChatResp
	if err := json.Unmarshal(body, &r); err != nil {
		return Usage{Recognised: true}
	}
	return Usage{
		Model:      r.Model,
		TokensIn:   r.Usage.PromptTokens,
		TokensOut:  r.Usage.CompletionTokens,
		Recognised: true,
	}
}

type openaiResponsesResp struct {
	Model string `json:"model"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func parseOpenAIResponses(body []byte) Usage {
	var r openaiResponsesResp
	if err := json.Unmarshal(body, &r); err != nil {
		return Usage{Recognised: true}
	}
	return Usage{
		Model:      r.Model,
		TokensIn:   r.Usage.InputTokens,
		TokensOut:  r.Usage.OutputTokens,
		Recognised: true,
	}
}

type ollamaResp struct {
	Model           string `json:"model"`
	PromptEvalCount int    `json:"prompt_eval_count"`
	EvalCount       int    `json:"eval_count"`
}

func parseOllama(body []byte) Usage {
	var r ollamaResp
	if err := json.Unmarshal(body, &r); err != nil {
		return Usage{Recognised: true}
	}
	return Usage{
		Model:      r.Model,
		TokensIn:   r.PromptEvalCount,
		TokensOut:  r.EvalCount,
		Recognised: true,
	}
}
