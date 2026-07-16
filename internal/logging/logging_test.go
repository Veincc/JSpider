package logging

import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestNewWithWritersRoutesByLevel(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	log := NewWithWriters(false, &stdout, &stderr)

	log.Info("info %d", 1)
	log.Verbose("hidden")
	log.Warn("warning")
	log.LogError("fetch", "failed")

	if got := stdout.String(); !strings.Contains(got, "info 1") || strings.Contains(got, "hidden") {
		t.Fatalf("stdout = %q", got)
	}
	if got := stderr.String(); !strings.Contains(got, "[WARN] warning") || !strings.Contains(got, "[ERR] fetch: failed") {
		t.Fatalf("stderr = %q", got)
	}
}

func TestLoggerSerializesConcurrentVerboseWrites(t *testing.T) {
	var stdout bytes.Buffer
	log := NewWithWriters(true, &stdout, nil)

	const writers = 32
	const writesPerWriter = 100
	var wg sync.WaitGroup
	for writer := 0; writer < writers; writer++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			for write := 0; write < writesPerWriter; write++ {
				log.Verbose("writer=%d write=%d", writer, write)
			}
		}(writer)
	}
	wg.Wait()

	if got, want := strings.Count(stdout.String(), "\n"), writers*writesPerWriter; got != want {
		t.Fatalf("complete log lines = %d, want %d", got, want)
	}
}

func TestCopiedLoggerSerializesSharedWriter(t *testing.T) {
	var stdout bytes.Buffer
	original := NewWithWriters(true, &stdout, nil)
	copied := *original
	logs := []*Logger{original, &copied}

	const writers = 32
	const writesPerWriter = 100
	var wg sync.WaitGroup
	for writer := 0; writer < writers; writer++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			log := logs[writer%len(logs)]
			for write := 0; write < writesPerWriter; write++ {
				log.Verbose("writer=%d write=%d", writer, write)
			}
		}(writer)
	}
	wg.Wait()

	if got, want := strings.Count(stdout.String(), "\n"), writers*writesPerWriter; got != want {
		t.Fatalf("complete log lines = %d, want %d", got, want)
	}
}

func TestZeroValueLoggerUsesProcessOutput(t *testing.T) {
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStdout, originalStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdoutWriter, stderrWriter
	t.Cleanup(func() {
		os.Stdout, os.Stderr = originalStdout, originalStderr
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		_ = stderrReader.Close()
		_ = stderrWriter.Close()
	})

	var log Logger
	log.Info("zero info")
	log.Error("zero error")
	if err := stdoutWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stderrWriter.Close(); err != nil {
		t.Fatal(err)
	}
	stdout, err := io.ReadAll(stdoutReader)
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := io.ReadAll(stderrReader)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(stdout), "zero info") {
		t.Fatalf("stdout = %q, want zero-value info output", stdout)
	}
	if !strings.Contains(string(stderr), "[ERROR] zero error") {
		t.Fatalf("stderr = %q, want zero-value error output", stderr)
	}
}
