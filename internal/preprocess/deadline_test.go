package preprocess

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSourceMapInputLimitAllowsExactBoundaryAndRejectsFetchedOverflow(t *testing.T) {
	data := make([]byte, maxSourceMapInputBytes+1)
	var target any
	err := decodeSourceMapJSON(context.Background(), data[:maxSourceMapInputBytes], &target)
	if errors.Is(err, errSourceMapTooLarge) {
		t.Fatal("exact-bound source map was rejected before JSON parsing")
	}

	p := &Processor{fetch: func(context.Context, string, string) ([]byte, error) {
		return data, nil
	}}
	if _, err := p.fetchSourceMap(context.Background(), "https://example.com/", "https://example.com/app.js.map"); !errors.Is(err, errSourceMapTooLarge) {
		t.Fatalf("oversized fetched source map error = %v, want %v", err, errSourceMapTooLarge)
	}
	_, status, _, err := p.recoverSourceMap(context.Background(), "https://example.com/", "https://example.com/app.js", "app.js.map")
	if status != "fetch_error" || !errors.Is(err, errSourceMapTooLarge) {
		t.Fatalf("oversized recovery status/error = %q/%v, want fetch_error/%v", status, err, errSourceMapTooLarge)
	}
}

func TestRecoverSourceMapInlineInputHonorsExactDecodedBoundary(t *testing.T) {
	const prefix = "data:application/json,"
	const document = `{"version":3}`
	var encoded strings.Builder
	encoded.Grow(len(prefix) + maxSourceMapInputBytes + 1)
	encoded.WriteString(prefix)
	encoded.WriteString(document)
	spaceChunk := strings.Repeat(" ", 64<<10)
	remaining := maxSourceMapInputBytes - len(document)
	for remaining >= len(spaceChunk) {
		encoded.WriteString(spaceChunk)
		remaining -= len(spaceChunk)
	}
	encoded.WriteString(spaceChunk[:remaining])

	p := &Processor{}
	exact := encoded.String()
	_, _, _, err := p.recoverSourceMap(context.Background(), "https://example.com/", "https://example.com/app.js", exact)
	if err != nil {
		t.Fatalf("exact-bound inline source map error = %v", err)
	}
	encoded.WriteByte(' ')
	_, status, _, err := p.recoverSourceMap(context.Background(), "https://example.com/", "https://example.com/app.js", encoded.String())
	if status != "parse_error" || !errors.Is(err, errSourceMapTooLarge) {
		t.Fatalf("oversized inline recovery status/error = %q/%v, want parse_error/%v", status, err, errSourceMapTooLarge)
	}
}

func TestDecodeSourceMapJSONHonorsContextAndSingleValueContract(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var target any
	if err := decodeSourceMapJSON(ctx, []byte(`{"version":3}`), &target); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled decode error = %v, want context.Canceled", err)
	}
	if err := decodeSourceMapJSON(context.Background(), []byte(`{"version":3} {"version":3}`), &target); err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("multiple JSON values error = %v", err)
	}
	if err := decodeSourceMapJSON(context.Background(), []byte("{} \n\t"), &target); err != nil {
		t.Fatalf("trailing JSON whitespace was rejected: %v", err)
	}
}

func TestBase64DecodedLengthUsesDecodedBoundaryAndIgnoresNewlines(t *testing.T) {
	exactEncoded := base64.StdEncoding.EncodedLen(maxSourceMapInputBytes)
	exactPadding := (3 - maxSourceMapInputBytes%3) % 3
	if got, err := checkedBase64DecodedLength(exactEncoded, exactPadding); err != nil || got != maxSourceMapInputBytes {
		t.Fatalf("exact decoded length = %d, error = %v", got, err)
	}
	overEncoded := base64.StdEncoding.EncodedLen(maxSourceMapInputBytes + 1)
	overPadding := (3 - (maxSourceMapInputBytes+1)%3) % 3
	if _, err := checkedBase64DecodedLength(overEncoded, overPadding); !errors.Is(err, errSourceMapTooLarge) {
		t.Fatalf("oversized decoded length error = %v, want %v", err, errSourceMapTooLarge)
	}

	payload := "eyJ2ZXJzaW9u\r\nIjozfQ=="
	data, err := decodeSourceMapDataURL(context.Background(), "data:application/json;base64,"+payload)
	if err != nil || string(data) != `{"version":3}` {
		t.Fatalf("newline base64 decode = %q, error = %v", data, err)
	}
}

func TestPercentDecodedLengthUsesDecodedBoundaryAndValidatesEscapes(t *testing.T) {
	if got, err := checkedPercentDecodedLength(maxSourceMapInputBytes+2, 1); err != nil || got != maxSourceMapInputBytes {
		t.Fatalf("exact percent-decoded length = %d, error = %v", got, err)
	}
	if _, err := checkedPercentDecodedLength(maxSourceMapInputBytes+1, 0); !errors.Is(err, errSourceMapTooLarge) {
		t.Fatalf("oversized percent-decoded length error = %v, want %v", err, errSourceMapTooLarge)
	}
	data, err := decodeSourceMapDataURL(context.Background(), "data:application/json,%7B%22version%22%3A3%7D")
	if err != nil || string(data) != `{"version":3}` {
		t.Fatalf("percent decode = %q, error = %v", data, err)
	}
	if _, err := decodeSourceMapDataURL(context.Background(), "data:application/json,%GG"); err == nil {
		t.Fatal("invalid percent escape was accepted")
	}
}

func TestDecodeSourceMapDataURLHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := decodeSourceMapDataURL(ctx, "data:application/json,%7B%7D"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled data URL error = %v, want context.Canceled", err)
	}
}

func TestRunSourceMapAttemptDoesNotStartWorkForCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	called := false
	_, err := runSourceMapAttempt(ctx, func(context.Context) (sourceMapRecovery, error) {
		called = true
		return sourceMapRecovery{}, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runSourceMapAttempt() error = %v, want context.Canceled", err)
	}
	if called {
		t.Fatal("runSourceMapAttempt() started work for an already-canceled context")
	}
}

func TestExtractSourceMapReferenceContextHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := extractSourceMapReferenceContext(ctx, []byte("const value = true;")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled source-map scan error = %v, want context.Canceled", err)
	}
}

func TestExtractSourceMapReferenceContextRestoresCallerBackingBuffer(t *testing.T) {
	sourceText := "const value = true;"
	backing := make([]byte, len(sourceText)+1)
	copy(backing, sourceText)
	backing[len(sourceText)] = 0x7f
	if _, err := extractSourceMapReferenceContext(context.Background(), backing[:len(sourceText)]); err != nil {
		t.Fatal(err)
	}
	if backing[len(sourceText)] != 0x7f {
		t.Fatalf("byte beyond source length = %#x, want restored sentinel", backing[len(sourceText)])
	}
}

func TestSourceMapJSONPresentHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sourceMapJSONPresent(ctx, []byte("  null  ")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled JSON presence error = %v, want context.Canceled", err)
	}
	if _, err := sourceMapStringPresent(ctx, "   "); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled string presence error = %v, want context.Canceled", err)
	}
}

func TestSourceMapTraversalPropagatesCancellationFromNestedFetch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	p := &Processor{fetch: func(ctx context.Context, _, _ string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	resolver := sourceMapResolver{p: p, entryURL: "https://example.com/", ctx: ctx}
	root := []byte(`{"version":3,"sections":[{"offset":{"line":0,"column":0},"url":"nested.map"}]}`)
	_, err := resolver.collect(root, "https://example.com/root.map", 0, map[string]bool{"https://example.com/root.map": true})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("nested traversal error = %v, want context.DeadlineExceeded", err)
	}
}

func TestRecoverSourceMapKeepsMalformedMapNonFatalButPropagatesCancellation(t *testing.T) {
	p := &Processor{fetch: func(context.Context, string, string) ([]byte, error) {
		return []byte(`{"version":`), nil
	}}
	_, _, recovery, err := p.recoverSourceMap(context.Background(), "https://example.com/", "https://example.com/app.js", "app.js.map")
	if err != nil || len(recovery.Files) != 0 {
		t.Fatalf("malformed recovery = %+v, error = %v, want incomplete nonfatal recovery", recovery, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, err = p.recoverSourceMap(ctx, "https://example.com/", "https://example.com/app.js", "app.js.map")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled recovery error = %v, want context.Canceled", err)
	}
}
