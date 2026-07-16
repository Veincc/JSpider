package preprocess

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type actorRequest struct {
	ctx    context.Context
	warmup bool
	source []byte
	reply  chan actorResult
}

type actorResult struct {
	code []byte
	err  error
}

type workerActor struct {
	nodePath       string
	helperPath     string
	processTimeout time.Duration
	startupTimeout time.Duration

	requests chan actorRequest
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

func newWorkerActor(nodePath, helperPath string, processTimeout, startupTimeout time.Duration) *workerActor {
	a := &workerActor{
		nodePath:       nodePath,
		helperPath:     helperPath,
		processTimeout: processTimeout,
		startupTimeout: startupTimeout,
		requests:       make(chan actorRequest),
		stop:           make(chan struct{}),
		done:           make(chan struct{}),
	}
	go a.run()
	return a
}

func (a *workerActor) warmup() error {
	result := a.submit(actorRequest{ctx: context.Background(), warmup: true, reply: make(chan actorResult, 1)})
	return result.err
}

func (a *workerActor) process(source []byte) ([]byte, error) {
	return a.processContext(context.Background(), source)
}

func (a *workerActor) processContext(ctx context.Context, source []byte) ([]byte, error) {
	result := a.submit(actorRequest{ctx: processingContext(ctx), source: source, reply: make(chan actorResult, 1)})
	return result.code, result.err
}

func (a *workerActor) submit(request actorRequest) actorResult {
	request.ctx = processingContext(request.ctx)
	select {
	case a.requests <- request:
	case <-request.ctx.Done():
		return actorResult{err: request.ctx.Err()}
	case <-a.stop:
		return actorResult{err: errors.New("audit-prep processor is closed")}
	case <-a.done:
		return actorResult{err: errors.New("audit-prep worker actor stopped")}
	}

	select {
	case result := <-request.reply:
		if err := request.ctx.Err(); err != nil {
			return actorResult{err: err}
		}
		return result
	case <-request.ctx.Done():
		return actorResult{err: request.ctx.Err()}
	case <-a.done:
		return actorResult{err: errors.New("audit-prep worker actor stopped")}
	}
}

func (a *workerActor) close() error {
	a.stopOnce.Do(func() { close(a.stop) })
	<-a.done
	return nil
}

func (a *workerActor) run() {
	defer close(a.done)
	var worker *nodeWorker
	defer func() {
		if worker != nil {
			worker.finish(true)
		}
	}()

	for {
		select {
		case <-a.stop:
			return
		case request := <-a.requests:
			request.ctx = processingContext(request.ctx)
			if err := request.ctx.Err(); err != nil {
				request.reply <- actorResult{err: err}
				continue
			}
			if worker == nil {
				var err error
				worker, err = startNodeWorker(a.nodePath, a.helperPath)
				if err == nil {
					err = a.checkWorker(request.ctx, worker)
				}
				if err != nil {
					if worker != nil {
						worker.finish(false)
						worker = nil
					}
					request.reply <- actorResult{err: err}
					continue
				}
			}

			if request.warmup {
				if err := request.ctx.Err(); err != nil {
					request.reply <- actorResult{err: err}
					continue
				}
				request.reply <- actorResult{}
				continue
			}

			response, fatal, err := worker.exchange(
				request.ctx,
				workerRequest{ID: worker.nextRequestID(), Source: string(request.source)},
				a.processTimeout,
				a.stop,
			)
			if err == nil {
				if !response.idPresent || !response.okPresent || (response.OK && !response.codePresent) {
					err = errors.New("invalid audit-prep process response schema")
					fatal = true
				}
			}
			if err == nil && !response.OK {
				err = errors.New(response.Error)
				if response.Error == "" {
					err = errors.New("audit-prep processing failed")
				}
			}
			if fatal {
				worker.finish(false)
				worker = nil
			}
			if err != nil {
				request.reply <- actorResult{err: err}
				continue
			}
			request.reply <- actorResult{code: []byte(response.Code)}
		}
	}
}

func (a *workerActor) checkWorker(ctx context.Context, worker *nodeWorker) error {
	response, _, err := worker.exchange(ctx, workerRequest{Command: "ping"}, a.startupTimeout, a.stop)
	if err != nil {
		return fmt.Errorf("start audit-prep worker: %w", err)
	}
	if !response.idPresent || !response.okPresent || (response.OK && !response.nodeVersionPresent) {
		return errors.New("invalid audit-prep ping response schema")
	}
	if !response.OK {
		if response.Error == "" {
			response.Error = "audit-prep worker failed to start"
		}
		return errors.New(response.Error)
	}
	majorText, _, _ := strings.Cut(response.NodeVersion, ".")
	major, err := strconv.Atoi(majorText)
	if err != nil || major < 18 {
		return errors.New(NodeVersionError)
	}
	return nil
}

type nodeWorker struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *json.Decoder

	stderr   strings.Builder
	stderrMu sync.Mutex
	nextID   int

	finishOnce sync.Once
	finished   chan struct{}
}

func startNodeWorker(nodePath, helperPath string) (*nodeWorker, error) {
	cmd := exec.Command(nodePath, helperPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("open audit-prep stdin: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("open audit-prep stdout: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("open audit-prep stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("start audit-prep worker: %w", err)
	}

	w := &nodeWorker{
		cmd:      cmd,
		stdin:    stdin,
		stdout:   json.NewDecoder(stdoutPipe),
		finished: make(chan struct{}),
	}
	go func() {
		_, _ = io.Copy(lockedWriter{mu: &w.stderrMu, writer: &w.stderr}, stderrPipe)
	}()
	return w, nil
}

func (w *nodeWorker) nextRequestID() int {
	w.nextID++
	return w.nextID
}

type exchangeResult struct {
	response workerResponse
	err      error
}

func (w *nodeWorker) exchange(ctx context.Context, request workerRequest, timeout time.Duration, stop <-chan struct{}) (workerResponse, bool, error) {
	ctx = processingContext(ctx)
	if err := ctx.Err(); err != nil {
		return workerResponse{}, true, err
	}
	deadlineLimited := false
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return workerResponse{}, true, context.DeadlineExceeded
		}
		if remaining < timeout {
			timeout = remaining
			deadlineLimited = true
		}
	}
	result := make(chan exchangeResult, 1)
	go func() {
		if err := json.NewEncoder(w.stdin).Encode(request); err != nil {
			result <- exchangeResult{err: fmt.Errorf("send audit-prep request: %w", err)}
			return
		}
		var response workerResponse
		if err := w.stdout.Decode(&response); err != nil {
			errText := "audit-prep worker stopped"
			if !errors.Is(err, io.EOF) {
				errText = fmt.Sprintf("decode audit-prep response: %v", err)
			}
			if stderr := strings.TrimSpace(w.stderrString()); stderr != "" {
				errText += ": " + stderr
			}
			result <- exchangeResult{err: errors.New(errText)}
			return
		}
		if response.ID != request.ID {
			result <- exchangeResult{err: fmt.Errorf("audit-prep response id mismatch: got %d want %d", response.ID, request.ID)}
			return
		}
		result <- exchangeResult{response: response}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case exchange := <-result:
		return exchange.response, exchange.err != nil, exchange.err
	case <-timer.C:
		w.finish(false)
		if deadlineLimited {
			if err := ctx.Err(); err != nil {
				return workerResponse{}, true, err
			}
			return workerResponse{}, true, context.DeadlineExceeded
		}
		return workerResponse{}, true, fmt.Errorf("audit-prep worker timeout after %s", timeout)
	case <-ctx.Done():
		w.finish(false)
		return workerResponse{}, true, ctx.Err()
	case <-stop:
		w.finish(false)
		return workerResponse{}, true, errors.New("audit-prep processor closed while worker was running")
	}
}

func (w *nodeWorker) finish(graceful bool) {
	w.finishOnce.Do(func() {
		go w.finishProcess(graceful)
	})
	<-w.finished
}

func (w *nodeWorker) finishProcess(graceful bool) {
	if graceful {
		go func() {
			_ = json.NewEncoder(w.stdin).Encode(workerRequest{Command: "shutdown"})
			_ = w.stdin.Close()
		}()
	} else {
		_ = w.cmd.Process.Kill()
		_ = w.stdin.Close()
	}

	waited := make(chan struct{})
	go func() {
		_ = w.cmd.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-time.After(2 * time.Second):
		_ = w.cmd.Process.Kill()
		<-waited
	}
	close(w.finished)
}

func (w *nodeWorker) stderrString() string {
	w.stderrMu.Lock()
	defer w.stderrMu.Unlock()
	return w.stderr.String()
}

type lockedWriter struct {
	mu     *sync.Mutex
	writer io.Writer
}

func (w lockedWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(data)
}
