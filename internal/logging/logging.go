package logging

import (
	"fmt"
	"os"
	"sync"
	"time"
)

type Logger struct {
	verbose    bool
	errFile    *os.File
	errMu      sync.Mutex
}

func New(verbose bool, outDir string) *Logger {
	logPath := outDir + "/analysis_errors.log"
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: cannot create error log file %s: %v\n", logPath, err)
		f = nil
	}
	return &Logger{verbose: verbose, errFile: f}
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
	line := fmt.Sprintf("[%s] [%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), context, msg)
	fmt.Fprintf(os.Stderr, "[%s] [ERR] %s: %s\n", time.Now().Format("15:04:05"), context, msg)

	if l.errFile != nil {
		l.errMu.Lock()
		l.errFile.WriteString(line)
		l.errMu.Unlock()
	}
}

func (l *Logger) Close() {
	if l.errFile != nil {
		l.errFile.Close()
	}
}
