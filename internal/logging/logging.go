package logging

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Logger struct {
	mu      sync.Mutex
	verbose bool
	stdout  io.Writer
	stderr  io.Writer
}

func New(verbose bool, _ string) *Logger {
	return NewWithWriters(verbose, os.Stdout, os.Stderr)
}

func NewWithWriters(verbose bool, stdout, stderr io.Writer) *Logger {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	return &Logger{verbose: verbose, stdout: stdout, stderr: stderr}
}

func (l *Logger) Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.mu.Lock()
	defer l.mu.Unlock()
	stdout := l.stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	fmt.Fprintf(stdout, "[%s] %s\n", time.Now().Format("15:04:05"), msg)
}

func (l *Logger) Verbose(format string, args ...interface{}) {
	if l.verbose {
		msg := fmt.Sprintf(format, args...)
		l.mu.Lock()
		defer l.mu.Unlock()
		stdout := l.stdout
		if stdout == nil {
			stdout = os.Stdout
		}
		fmt.Fprintf(stdout, "[%s] [V] %s\n", time.Now().Format("15:04:05"), msg)
	}
}

func (l *Logger) Warn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.mu.Lock()
	defer l.mu.Unlock()
	stderr := l.stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	fmt.Fprintf(stderr, "[%s] [WARN] %s\n", time.Now().Format("15:04:05"), msg)
}

func (l *Logger) Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.mu.Lock()
	defer l.mu.Unlock()
	stderr := l.stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	fmt.Fprintf(stderr, "[%s] [ERROR] %s\n", time.Now().Format("15:04:05"), msg)
}

func (l *Logger) LogError(context, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.mu.Lock()
	defer l.mu.Unlock()
	stderr := l.stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	fmt.Fprintf(stderr, "[%s] [ERR] %s: %s\n", time.Now().Format("15:04:05"), context, msg)
}

func (l *Logger) Close() {}
