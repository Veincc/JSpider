// Package apidiscovery extracts API candidates from JavaScript, normalizes
// browser requests, associates static and runtime evidence, and writes reports.
package apidiscovery

const (
	Version                = 1
	RedactedValue          = "[REDACTED]"
	MaxParameterValueBytes = 128
	MaxRequestBodyBytes    = 64 * 1024
	MaxBodySampleBytes     = 4 * 1024
)

type Confidence string

const (
	ConfidenceConfirmed Confidence = "confirmed"
	ConfidenceCandidate Confidence = "candidate"
)

type EndpointKind string

const (
	EndpointMatched     EndpointKind = "matched"
	EndpointRuntimeOnly EndpointKind = "runtime_only"
	EndpointStaticOnly  EndpointKind = "static_only"
)

type Parameter struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

type StaticEndpoint struct {
	Version     int               `json:"version"`
	RawURL      string            `json:"raw_url"`
	Method      string            `json:"method,omitempty"`
	QueryParams []Parameter       `json:"query_params"`
	BodyParams  []Parameter       `json:"body_params"`
	Headers     map[string]string `json:"headers,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Type        string            `json:"type,omitempty"`
	Source      string            `json:"source,omitempty"`
	SourceJSURL string            `json:"source_js_url"`
}

type Initiator struct {
	Type      string   `json:"type,omitempty"`
	URL       string   `json:"url,omitempty"`
	StackURLs []string `json:"stack_urls"`
}

type BodyInfo struct {
	ContentType string       `json:"content_type,omitempty"`
	HasBody     bool         `json:"has_body"`
	Params      []Parameter  `json:"params"`
	Sample      string       `json:"sample,omitempty"`
	GraphQL     *GraphQLInfo `json:"graphql,omitempty"`
}

type GraphQLInfo struct {
	OperationName string   `json:"operation_name,omitempty"`
	Variables     []string `json:"variables"`
}

type RequestData struct {
	Headers     map[string]string `json:"headers,omitempty"`
	QueryParams []Parameter       `json:"query_params"`
	Body        BodyInfo          `json:"body"`
}

type RuntimeRequest struct {
	Version           int               `json:"version"`
	RequestID         string            `json:"request_id"`
	RedirectIndex     int               `json:"redirect_index,omitempty"`
	URL               string            `json:"url"`
	Method            string            `json:"method"`
	ResourceType      string            `json:"resource_type"`
	Stage             string            `json:"stage"`
	EntryURL          string            `json:"entry_url,omitempty"`
	DocumentURL       string            `json:"document_url,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	QueryParams       []Parameter       `json:"query_params"`
	BodyParams        []Parameter       `json:"body_params"`
	ContentType       string            `json:"content_type,omitempty"`
	HasBody           bool              `json:"has_body"`
	BodySample        string            `json:"body_sample,omitempty"`
	GraphQL           *GraphQLInfo      `json:"graphql,omitempty"`
	Initiator         Initiator         `json:"initiator"`
	StatusCode        int64             `json:"status_code,omitempty"`
	MimeType          string            `json:"mime_type,omitempty"`
	Completed         bool              `json:"completed"`
	Failed            bool              `json:"failed"`
	ErrorText         string            `json:"error_text,omitempty"`
	EncodedDataLength float64           `json:"encoded_data_length,omitempty"`
	RedirectFrom      string            `json:"redirect_from,omitempty"`
	RedirectTo        string            `json:"redirect_to,omitempty"`
	Preflight         bool              `json:"preflight"`
	WebSocket         bool              `json:"websocket"`
}

type Association struct {
	Version        int        `json:"version"`
	StaticRawURL   string     `json:"static_raw_url"`
	RuntimeURL     string     `json:"runtime_url"`
	Method         string     `json:"method,omitempty"`
	Score          int        `json:"score"`
	Confidence     Confidence `json:"confidence"`
	RuntimeOrigin  string     `json:"runtime_origin"`
	Prefix         string     `json:"prefix"`
	RuntimeBase    string     `json:"runtime_base"`
	SourceJSURL    string     `json:"source_js_url,omitempty"`
	InitiatorExact bool       `json:"initiator_exact"`
	UsedExpression bool       `json:"used_expr"`
	Evidence       []string   `json:"evidence"`
}

type MatchedPair struct {
	StaticRawURL string `json:"static_raw_url"`
	RuntimeURL   string `json:"runtime_url"`
	Score        int    `json:"score"`
}

type RuntimeBase struct {
	Version       int           `json:"version"`
	Origin        string        `json:"origin"`
	Prefix        string        `json:"prefix"`
	RuntimeBase   string        `json:"runtime_base"`
	Confidence    Confidence    `json:"confidence"`
	EvidenceCount int           `json:"evidence_count"`
	MatchedPairs  []MatchedPair `json:"matched_pairs"`
}

type Endpoint struct {
	Version            int          `json:"version"`
	Kind               EndpointKind `json:"kind"`
	RawURL             string       `json:"raw_url,omitempty"`
	ResolvedURL        string       `json:"resolved_url,omitempty"`
	ResolvedCandidates []string     `json:"resolved_candidates"`
	Method             string       `json:"method,omitempty"`
	Confidence         Confidence   `json:"confidence"`
	Score              int          `json:"score,omitempty"`
	SourceJSURLs       []string     `json:"source_js_urls"`
	RuntimeStatus      int64        `json:"runtime_status,omitempty"`
	RuntimeFailed      bool         `json:"runtime_failed,omitempty"`
	QueryParams        []Parameter  `json:"query_params"`
	BodyParams         []Parameter  `json:"body_params"`
	Evidence           []string     `json:"evidence"`
}

type Summary struct {
	Static    int `json:"static"`
	Runtime   int `json:"runtime"`
	Matched   int `json:"matched"`
	Confirmed int `json:"confirmed"`
	Bases     int `json:"bases"`
}

// SourceIdentity preserves the crawl context for a downloaded JavaScript
// source without changing the URL-keyed matching behavior. A later matching
// revision can consume the richer identity without forcing callers to recover
// it from sanitized output paths.
type SourceIdentity struct {
	EntryURL     string `json:"entry_url"`
	RequestedURL string `json:"requested_url"`
	FinalURL     string `json:"final_url"`
	ContentHash  string `json:"content_hash"`
}

// SessionStats is a cheap collection snapshot. It deliberately reports
// collected sources and runtime API requests only; it never triggers static
// analysis or builds a report.
type SessionStats struct {
	Sources int `json:"sources"`
	Runtime int `json:"runtime"`
}

type Report struct {
	StaticEndpoints []StaticEndpoint
	RuntimeRequests []RuntimeRequest
	Associations    []Association
	Endpoints       []Endpoint
	Bases           []RuntimeBase
	Summary         Summary
}
