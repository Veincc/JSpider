package logging

import (
	"fmt"
	"os"
	"time"
)

type Logger struct {
	verbose bool
}

func New(verbose bool, _ string) *Logger {
	return &Logger{verbose: verbose}
}

func (l *Logger) Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("[%s] %s\n", time.Now().Format("15:04:05"), msg)
}

func (l *Logger) Verbose(format string, args ...interface{}) {
	if l.verbose {
		msg := fmt.Sprintf(format, args...)
		fmt.Printf("[%s] [V] %s\n", time.Now().Format("15:04:05"), msg)
	}
}

func (l *Logger) Warn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "[%s] [WARN] %s\n", time.Now().Format("15:04:05"), msg)
}

func (l *Logger) Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "[%s] [ERROR] %s\n", time.Now().Format("15:04:05"), msg)
}

func (l *Logger) LogError(context, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "[%s] [ERR] %s: %s\n", time.Now().Format("15:04:05"), context, msg)
}

func (l *Logger) Close() {}
