package logging

import (
	"fmt"
	"io"
	"os"
	"time"
)

type Logger struct {
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
	fmt.Fprintf(l.stdout, "[%s] %s\n", time.Now().Format("15:04:05"), msg)
}

func (l *Logger) Verbose(format string, args ...interface{}) {
	if l.verbose {
		msg := fmt.Sprintf(format, args...)
		fmt.Fprintf(l.stdout, "[%s] [V] %s\n", time.Now().Format("15:04:05"), msg)
	}
}

func (l *Logger) Warn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.stderr, "[%s] [WARN] %s\n", time.Now().Format("15:04:05"), msg)
}

func (l *Logger) Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.stderr, "[%s] [ERROR] %s\n", time.Now().Format("15:04:05"), msg)
}

func (l *Logger) LogError(context, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.stderr, "[%s] [ERR] %s: %s\n", time.Now().Format("15:04:05"), context, msg)
}

func (l *Logger) Close() {}
