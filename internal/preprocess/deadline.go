package preprocess

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unicode"
)

const maxSourceMapInputBytes = 128 << 20

var errSourceMapTooLarge = fmt.Errorf("source map exceeds %d-byte input limit", maxSourceMapInputBytes)

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func processingContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func checkSourceMapInputLength(length int) error {
	if length > maxSourceMapInputBytes {
		return errSourceMapTooLarge
	}
	return nil
}

func decodeSourceMapJSON(ctx context.Context, data []byte, target any) error {
	ctx = processingContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := checkSourceMapInputLength(len(data)); err != nil {
		return err
	}

	decoder := json.NewDecoder(contextReader{ctx: ctx, r: bytes.NewReader(data)})
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple source-map JSON values")
		}
		return err
	}
	return ctx.Err()
}

func sourceMapJSONPresent(ctx context.Context, data []byte) (bool, error) {
	ctx = processingContext(ctx)
	start := 0
	for start < len(data) && isJSONWhitespace(data[start]) {
		if start&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return false, err
			}
		}
		start++
	}
	end := len(data)
	for end > start && isJSONWhitespace(data[end-1]) {
		if end&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return false, err
			}
		}
		end--
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if end == start {
		return false, nil
	}
	isNull := end-start == 4 && data[start] == 'n' && data[start+1] == 'u' && data[start+2] == 'l' && data[start+3] == 'l'
	return !isNull, nil
}

func sourceMapStringPresent(ctx context.Context, value string) (bool, error) {
	ctx = processingContext(ctx)
	for index, current := range value {
		if index&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return false, err
			}
		}
		if !unicode.IsSpace(current) {
			return true, nil
		}
	}
	return false, ctx.Err()
}

func isJSONWhitespace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n'
}

func checkedBase64DecodedLength(encodedLength, padding int) (int, error) {
	if encodedLength < 0 || padding < 0 || padding > 2 || encodedLength%4 != 0 || padding > encodedLength {
		return 0, errors.New("invalid base64 source map length")
	}
	decodedLength := base64.StdEncoding.DecodedLen(encodedLength) - padding
	if err := checkSourceMapInputLength(decodedLength); err != nil {
		return 0, err
	}
	return decodedLength, nil
}

func base64DecodedLength(ctx context.Context, payload string) (int, error) {
	ctx = processingContext(ctx)
	encodedLength := 0
	padding := 0
	seenPadding := false
	for index := 0; index < len(payload); index++ {
		if index&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
		}
		switch payload[index] {
		case '\r', '\n':
			continue
		case '=':
			seenPadding = true
			padding++
			encodedLength++
		default:
			if seenPadding {
				return 0, errors.New("invalid base64 source map padding")
			}
			encodedLength++
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return checkedBase64DecodedLength(encodedLength, padding)
}

func checkedPercentDecodedLength(encodedLength, escapeCount int) (int, error) {
	if encodedLength < 0 || escapeCount < 0 || escapeCount > encodedLength/3 {
		return 0, errors.New("invalid percent-encoded source map length")
	}
	decodedLength := encodedLength - 2*escapeCount
	if err := checkSourceMapInputLength(decodedLength); err != nil {
		return 0, err
	}
	return decodedLength, nil
}

func percentDecodedLength(ctx context.Context, payload string) (int, error) {
	ctx = processingContext(ctx)
	escapeCount := 0
	for index := 0; index < len(payload); index++ {
		if index&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
		}
		if payload[index] != '%' {
			continue
		}
		if index+2 >= len(payload) || !isHexDigit(payload[index+1]) || !isHexDigit(payload[index+2]) {
			end := index + 3
			if end > len(payload) {
				end = len(payload)
			}
			return 0, url.EscapeError(payload[index:end])
		}
		escapeCount++
		index += 2
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return checkedPercentDecodedLength(len(payload), escapeCount)
}

func isHexDigit(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func decodeSourceMapDataURL(ctx context.Context, value string) ([]byte, error) {
	ctx = processingContext(ctx)
	comma, err := dataURLComma(ctx, value)
	if err != nil {
		return nil, err
	}
	if comma < 0 {
		return nil, errors.New("invalid source map data URL")
	}
	metadata := value[:comma]
	payload := value[comma+1:]

	var decoded []byte
	if containsASCIIFoldContext(ctx, metadata, ";base64") {
		decodedLength, err := base64DecodedLength(ctx, payload)
		if err != nil {
			return nil, err
		}
		decoded = make([]byte, decodedLength)
		decoder := base64.NewDecoder(base64.StdEncoding, contextReader{ctx: ctx, r: strings.NewReader(payload)})
		if _, err := io.ReadFull(decoder, decoded); err != nil {
			return nil, err
		}
		var extra [1]byte
		if count, err := decoder.Read(extra[:]); count != 0 || !errors.Is(err, io.EOF) {
			if err == nil {
				return nil, errors.New("base64 source map decoded past expected length")
			}
			return nil, err
		}
	} else {
		decodedLength, err := percentDecodedLength(ctx, payload)
		if err != nil {
			return nil, err
		}
		decodedText, err := url.PathUnescape(payload)
		if err != nil {
			return nil, err
		}
		if len(decodedText) != decodedLength {
			return nil, errors.New("percent-decoded source map length mismatch")
		}
		decoded = []byte(decodedText)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkSourceMapInputLength(len(decoded)); err != nil {
		return nil, err
	}
	return decoded, nil
}

func dataURLComma(ctx context.Context, value string) (int, error) {
	for index := 0; index < len(value); index++ {
		if index&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return -1, err
			}
		}
		if value[index] == ',' {
			return index, nil
		}
	}
	return -1, ctx.Err()
}

func containsASCIIFoldContext(ctx context.Context, value, target string) bool {
	if len(target) == 0 {
		return true
	}
	for start := 0; start+len(target) <= len(value); start++ {
		if start&4095 == 0 && ctx.Err() != nil {
			return false
		}
		if strings.EqualFold(value[start:start+len(target)], target) {
			return true
		}
	}
	return false
}

type sourceMapAttemptResult struct {
	recovery sourceMapRecovery
	err      error
}

func runSourceMapAttempt(ctx context.Context, work func(context.Context) (sourceMapRecovery, error)) (sourceMapRecovery, error) {
	ctx = processingContext(ctx)
	if err := ctx.Err(); err != nil {
		return sourceMapRecovery{}, err
	}
	select {
	case sourceMapWorkSlots <- struct{}{}:
	case <-ctx.Done():
		return sourceMapRecovery{}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		<-sourceMapWorkSlots
		return sourceMapRecovery{}, err
	}

	result := make(chan sourceMapAttemptResult, 1)
	go func() {
		defer func() { <-sourceMapWorkSlots }()
		recovery, err := work(ctx)
		result <- sourceMapAttemptResult{recovery: recovery, err: err}
	}()

	select {
	case got := <-result:
		return got.recovery, got.err
	case <-ctx.Done():
		return sourceMapRecovery{}, ctx.Err()
	}
}
