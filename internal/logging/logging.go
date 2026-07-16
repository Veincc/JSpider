package logging

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Logger struct {
	verbose bool
	state   *loggerState
}

type loggerState struct {
	mu     sync.Mutex
	stdout io.Writer
	stderr io.Writer
}

var processOutputState loggerState

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
	return &Logger{
		verbose: verbose,
		state:   &loggerState{stdout: stdout, stderr: stderr},
	}
}

func (l *Logger) sharedState() *loggerState {
	if l.state != nil {
		return l.state
	}
	return &processOutputState
}

func (l *Logger) Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	state := l.sharedState()
	state.mu.Lock()
	defer state.mu.Unlock()
	stdout := state.stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	fmt.Fprintf(stdout, "[%s] %s\n", time.Now().Format("15:04:05"), msg)
}

func (l *Logger) Verbose(format string, args ...interface{}) {
	if l.verbose {
		msg := fmt.Sprintf(format, args...)
		state := l.sharedState()
		state.mu.Lock()
		defer state.mu.Unlock()
		stdout := state.stdout
		if stdout == nil {
			stdout = os.Stdout
		}
		fmt.Fprintf(stdout, "[%s] [V] %s\n", time.Now().Format("15:04:05"), msg)
	}
}

func (l *Logger) Warn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	state := l.sharedState()
	state.mu.Lock()
	defer state.mu.Unlock()
	stderr := state.stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	fmt.Fprintf(stderr, "[%s] [WARN] %s\n", time.Now().Format("15:04:05"), msg)
}

func (l *Logger) Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	state := l.sharedState()
	state.mu.Lock()
	defer state.mu.Unlock()
	stderr := state.stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	fmt.Fprintf(stderr, "[%s] [ERROR] %s\n", time.Now().Format("15:04:05"), msg)
}

func (l *Logger) LogError(context, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	state := l.sharedState()
	state.mu.Lock()
	defer state.mu.Unlock()
	stderr := state.stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	fmt.Fprintf(stderr, "[%s] [ERR] %s: %s\n", time.Now().Format("15:04:05"), context, msg)
}

func (l *Logger) Close() {}
