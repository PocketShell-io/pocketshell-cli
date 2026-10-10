package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// The final bootstrap trust bridge (agreement §16, C-Fleet-native-entry-v1):
// with --spawn-entry the verifier
//  1. verifies every request, each content request against its EXPECTED
//     digest (BI1, native), and writes the protocol-v2 reply;
//  2. waits for the consumer's ONE correlated line
//     {"version":2,"operationId":OP,"op":"authorize"} — nothing is created
//     before it (EOF/foreign/malformed/timeout: nothing ran);
//  3. creates the entry from the HELD file — suspended, CREATE_NO_WINDOW,
//     its own closed environment, a verifier-owned job (KILL_ON_JOB_CLOSE,
//     BREAKAWAY_OK so the CLI's guardian/link can still break away) — proves
//     its kernel image is the held file, then resumes it;
//  4. owns the whole command tree (entry + bundled Python) until it is
//     PROVEN terminal, reads both output pipes to true EOF (bounded), and
//     reports launched -> exited -> released (exit 0), or a terminal event.

const (
	maxEntryOutput = 64 * 1024
	maxStderrTail  = 4 * 1024
	drainSeconds   = 10
)

// exitResult: the entry's measured exit code, or the measurement failure.
type exitResult struct {
	code int
	err  error
}

// child is the verifier-owned entry (and, natively, its job).
type child interface {
	PID() int
	Birth() string
	Stdout() io.Reader
	Stderr() io.Reader
	Exited() <-chan exitResult
	Terminate() bool // the WHOLE tree; true only when its end is PROVEN
}

// custodyError: the suspended entry was refused but could not be proven
// terminated; its exact identity (and handles) are retained.
type custodyError struct {
	pid   int
	birth string
	why   error
}

func (e *custodyError) Error() string {
	return fmt.Sprintf("%v; the suspended entry %d (birth %s) could not be proven terminated", e.why, e.pid, e.birth)
}

type spawner func(cfg config) (child, error)

type capture struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	limit    int
	tail     bool
	overflow bool
}

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tail {
		c.buf.Write(p)
		if c.buf.Len() > c.limit {
			b := append([]byte(nil), c.buf.Bytes()[c.buf.Len()-c.limit:]...)
			c.buf.Reset()
			c.buf.Write(b)
		}
		return len(p), nil
	}
	if c.buf.Len()+len(p) > c.limit {
		c.overflow = true
		return 0, errors.New("entry output exceeds 64 KiB")
	}
	return c.buf.Write(p)
}

func runEntry(cfg config, keep *held, in io.Reader, out *os.File, spawn spawner) int {
	ev := func(e event) {
		e.Version, e.OperationID = protocolVersion, cfg.OperationID
		emit(out, e)
	}
	problem := func(err error) *string {
		if err == nil {
			return nil
		}
		return strp(sanitize(err.Error()))
	}
	lines := make(chan input, 1)
	go func() {
		s := bufio.NewScanner(in)
		s.Buffer(make([]byte, 4096), 4096)
		for s.Scan() {
			lines <- input{line: append([]byte(nil), s.Bytes()...)}
		}
		if err := s.Err(); err != nil {
			lines <- input{err: err}
		} else {
			lines <- input{eof: true}
		}
	}()
	hold := time.NewTimer(time.Duration(cfg.HoldSeconds) * time.Second)

	// 1) the correlated authorize, BEFORE anything is created
	select {
	case <-hold.C:
		keep.closeAll()
		ev(event{Event: "timeout", Problem: strp("no authorize before --hold-timeout; nothing was started")})
		return 5
	case item := <-lines:
		switch {
		case item.eof:
			keep.closeAll()
			ev(event{Event: "closed", Problem: strp("controller closed stdin before authorize; nothing was started")})
			return 4
		case item.err != nil:
			keep.closeAll()
			ev(event{Event: "refused", Problem: problem(fmt.Errorf("unreadable authorize: %v", item.err))})
			return 2
		}
		if err := parseAuthorize(item.line, cfg.OperationID); err != nil {
			keep.closeAll()
			ev(event{Event: "refused", Problem: problem(fmt.Errorf("%v; nothing was started", err))})
			return 2
		}
	}

	// 2) create, prove, resume
	c, err := spawn(cfg)
	if err != nil {
		var custody *custodyError
		if errors.As(err, &custody) {
			pid, birth := custody.pid, custody.birth
			ev(event{Event: "unknown", PID: &pid, CreationFILETIME: &birth, Problem: problem(err)})
			return 6 // handles retained until this process ends; the consumer stays busy
		}
		keep.closeAll()
		ev(event{Event: "refused", Problem: problem(err)})
		return 1
	}
	pid, birth, yes := c.PID(), c.Birth(), true
	ev(event{Event: "launched", PID: &pid, CreationFILETIME: &birth, ImageMatches: &yes})

	stdout := &capture{limit: maxEntryOutput}
	stderr := &capture{limit: maxStderrTail, tail: true}
	stdoutEOF, stderrEOF := make(chan error, 1), make(chan error, 1)
	go func() { _, err := io.Copy(stdout, c.Stdout()); stdoutEOF <- err }()
	go func() { _, err := io.Copy(stderr, c.Stderr()); stderrEOF <- err }()

	seconds := cfg.EntrySeconds
	if seconds == 0 {
		seconds = cfg.HoldSeconds
	}
	deadline := time.NewTimer(time.Duration(seconds) * time.Second)
	// stop: end the whole tree; a terminal event only when the end is PROVEN
	stop := func(name string, code int, why error) int {
		for attempt := 0; attempt < 3; attempt++ {
			if c.Terminate() {
				keep.closeAll()
				ev(event{Event: name, PID: &pid, CreationFILETIME: &birth, Problem: problem(why)})
				return code
			}
			time.Sleep(time.Second)
		}
		ev(event{Event: "unknown", PID: &pid, CreationFILETIME: &birth,
			Problem: strp(sanitize(fmt.Sprintf("%v; the entry's termination could not be proven", why)))})
		return 6
	}
	stdoutDone := false
	for {
		select {
		case err := <-stdoutEOF:
			stdoutDone = true
			if stdout.overflow {
				return stop("refused", 2, errors.New("entry output exceeds 64 KiB"))
			}
			if err != nil {
				return stop("refused", 2, fmt.Errorf("entry output unreadable: %v", err))
			}
			stdoutEOF = nil
		case res := <-c.Exited():
			if res.err != nil { // NB3: never a synthetic success
				return stop("refused", 2, fmt.Errorf("the entry's exit could not be measured: %v", res.err))
			}
			// NB4: both pipes must reach TRUE EOF (bounded) before the result exists
			drain := time.NewTimer(drainSeconds * time.Second)
			for !stdoutDone || stderrEOF != nil {
				select {
				case err := <-stdoutEOF:
					stdoutDone = true
					stdoutEOF = nil
					if stdout.overflow || err != nil {
						return stop("refused", 2, errors.New("entry output exceeds 64 KiB or is unreadable"))
					}
				case <-stderrEOF:
					stderrEOF = nil
				case <-drain.C:
					return stop("refused", 2, errors.New("entry output did not reach end-of-file; result incomplete"))
				}
			}
			// the tree must be empty too (no descendant outlived the entry)
			if !c.Terminate() {
				return stop("refused", 2, errors.New("the entry's tree could not be proven ended"))
			}
			code := res.code
			data := stdout.buf.Bytes()
			b64, n, tail := base64.StdEncoding.EncodeToString(data), len(data), stderr.buf.String()
			ev(event{Event: "exited", PID: &pid, CreationFILETIME: &birth, ExitCode: &code, StdoutBase64: &b64,
				StdoutBytes: &n, StderrTail: &tail})
			keep.closeAll()
			ev(event{Event: "released"})
			return 0
		case <-deadline.C:
			return stop("timeout", 5, errors.New("the entry did not finish before --entry-timeout"))
		case item := <-lines:
			if item.eof {
				return stop("closed", 4, errors.New("controller closed stdin; the entry was ended"))
			}
			return stop("refused", 2, errors.New("no further input is accepted while the verifier owns the entry"))
		}
	}
}
