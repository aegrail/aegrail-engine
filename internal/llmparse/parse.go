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
	"net/http"
	"net/url"
	"strconv"
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
	// OpenAI-compatible shape (path-only; covers OpenAI, Azure OpenAI
	// proxies, litellm, vLLM, any gateway exposing the standard path).
	case strings.HasSuffix(path, "/v1/chat/completions"),
		strings.HasSuffix(path, "/v1/responses"):
		return true
	// Anthropic-compatible shape (path-only).
	case strings.HasSuffix(path, "/v1/messages"):
		return true
	// Bedrock (host-anchored because the path shape "/model/X/invoke"
	// is otherwise generic).
	case isBedrockRuntimeHost(host) && isBedrockInvokePath(path):
		return true
	// Vertex AI / Gemini (host-anchored on aiplatform / Gemini hosts;
	// path-anchored on the :generateContent / :predict suffix).
	case isVertexAIHost(host) && isVertexPath(path):
		return true
	// Ollama (any host — usually localhost / in-cluster service).
	case strings.HasSuffix(path, "/api/generate"),
		strings.HasSuffix(path, "/api/chat"):
		return true
	}
	return false
}

func isBedrockRuntimeHost(host string) bool {
	// bedrock-runtime.<region>.amazonaws.com
	return strings.HasPrefix(host, "bedrock-runtime.") &&
		strings.HasSuffix(host, ".amazonaws.com")
}

func isBedrockInvokePath(path string) bool {
	// /model/<id>/invoke, /model/<id>/invoke-with-response-stream,
	// /model/<id>/converse, /model/<id>/converse-stream
	if !strings.HasPrefix(path, "/model/") {
		return false
	}
	return strings.HasSuffix(path, "/invoke") ||
		strings.HasSuffix(path, "/invoke-with-response-stream") ||
		strings.HasSuffix(path, "/converse") ||
		strings.HasSuffix(path, "/converse-stream")
}

func isVertexAIHost(host string) bool {
	// us-central1-aiplatform.googleapis.com, etc.
	// Also: generativelanguage.googleapis.com (AI Studio / Gemini API)
	return strings.HasSuffix(host, "-aiplatform.googleapis.com") ||
		host == "aiplatform.googleapis.com" ||
		host == "generativelanguage.googleapis.com"
}

func isVertexPath(path string) bool {
	// Vertex AI: …:generateContent, :streamGenerateContent, :predict
	// Gemini AI Studio: /v1beta/models/<id>:generateContent
	return strings.Contains(path, ":generateContent") ||
		strings.Contains(path, ":streamGenerateContent") ||
		strings.Contains(path, ":predict")
}

// ParseResponse parses an LLM response and returns the extracted
// Usage. The headers argument is consulted for providers that
// report usage out-of-band (notably Bedrock, which puts token
// counts in x-amzn-bedrock-*-token-count response headers).
// Tolerant of unknown shapes — returns a zero Usage with
// Recognised=false rather than erroring.
func ParseResponse(reqURL *url.URL, body []byte, headers http.Header) Usage {
	if !Recognise(reqURL) {
		return Usage{}
	}
	host, path := reqURL.Hostname(), strings.TrimRight(reqURL.Path, "/")
	switch {
	case strings.HasSuffix(path, "/v1/chat/completions"):
		return parseOpenAIChat(body)
	case strings.HasSuffix(path, "/v1/responses"):
		return parseOpenAIResponses(body)
	case strings.HasSuffix(path, "/v1/messages"):
		return parseAnthropicMessages(body)
	case isBedrockRuntimeHost(host) && isBedrockInvokePath(path):
		return parseBedrock(body, headers, path)
	case isVertexAIHost(host) && isVertexPath(path):
		return parseVertex(body)
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

type anthropicMessagesResp struct {
	Model string `json:"model"`
	Usage struct {
		InputTokens              int `json:"input_tokens"`
		OutputTokens             int `json:"output_tokens"`
		CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
		CacheReadInputTokens     int `json:"cache_read_input_tokens"`
	} `json:"usage"`
}

func parseAnthropicMessages(body []byte) Usage {
	var r anthropicMessagesResp
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

// parseBedrock pulls token counts from Bedrock's response headers
// (x-amzn-bedrock-input-token-count, x-amzn-bedrock-output-token-count).
// The body is the wrapped provider payload (Anthropic, AI21, Cohere,
// Meta, etc.); model identification comes from the URL path
// (/model/<model-id>/invoke).
func parseBedrock(_ []byte, headers http.Header, path string) Usage {
	tokensIn, _ := strconv.Atoi(headers.Get("X-Amzn-Bedrock-Input-Token-Count"))
	tokensOut, _ := strconv.Atoi(headers.Get("X-Amzn-Bedrock-Output-Token-Count"))
	return Usage{
		Model:      modelIDFromBedrockPath(path),
		TokensIn:   tokensIn,
		TokensOut:  tokensOut,
		Recognised: true,
	}
}

// modelIDFromBedrockPath extracts the model id from a path like
// /model/anthropic.claude-3-5-sonnet-20240620-v1:0/invoke.
func modelIDFromBedrockPath(path string) string {
	const prefix = "/model/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := path[len(prefix):]
	for _, suffix := range []string{
		"/invoke-with-response-stream",
		"/invoke",
		"/converse-stream",
		"/converse",
	} {
		if strings.HasSuffix(rest, suffix) {
			return strings.TrimSuffix(rest, suffix)
		}
	}
	return rest
}

type vertexResp struct {
	// Gemini / Vertex generateContent shape
	UsageMetadata struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
		TotalTokenCount      int `json:"totalTokenCount"`
	} `json:"usageMetadata"`
	// Some Vertex responses include model name at top level
	ModelVersion string `json:"modelVersion"`
}

func parseVertex(body []byte) Usage {
	var r vertexResp
	if err := json.Unmarshal(body, &r); err != nil {
		return Usage{Recognised: true}
	}
	return Usage{
		Model:      r.ModelVersion,
		TokensIn:   r.UsageMetadata.PromptTokenCount,
		TokensOut:  r.UsageMetadata.CandidatesTokenCount,
		Recognised: true,
	}
}
