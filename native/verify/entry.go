package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// The final bootstrap trust bridge (agreement §16): with --spawn-entry the
// verifier itself creates the entry process from the HELD, verified file —
// suspended, CREATE_NO_WINDOW, closed (inherited) environment — checks that
// the suspended process's kernel image IS the held file (volume serial +
// file index) before resuming it, owns the child for the whole command, and
// returns its bounded stdout/exit code as events. Desktop never spawns the
// entry by pathname.

const (
	maxEntryOutput = 64 * 1024
	maxStderrTail  = 4 * 1024
)

// child is the verifier-owned entry process.
type child interface {
	PID() int
	Birth() string
	Stdout() io.Reader
	Stderr() io.Reader
	Exited() <-chan int // receives the exit code once the process has exited
	Terminate() bool    // exact handle; true only when the exit is PROVEN
}

// spawner creates the entry suspended, proves its image identity, resumes
// it, or fails (and leaves nothing running) before any instruction executed.
type spawner func(cfg config) (child, error)

type capture struct {
	buf      bytes.Buffer
	limit    int
	tail     bool
	overflow bool
	mu       sync.Mutex
}

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tail {
		c.buf.Write(p)
		if c.buf.Len() > c.limit {
			b := c.buf.Bytes()[c.buf.Len()-c.limit:]
			c.buf = *bytes.NewBuffer(append([]byte(nil), b...))
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
	c, err := spawn(cfg)
	if err != nil {
		keep.closeAll()
		ev(event{Event: "refused", Problem: problem(err)})
		return 1
	}
	pid, birth, yes := c.PID(), c.Birth(), true
	ev(event{Event: "launched", PID: &pid, CreationFILETIME: &birth, ImageMatches: &yes})

	stdout := &capture{limit: maxEntryOutput}
	stderr := &capture{limit: maxStderrTail, tail: true}
	var readers sync.WaitGroup
	readers.Add(2)
	overflow := make(chan struct{}, 1)
	go func() {
		defer readers.Done()
		if _, err := io.Copy(stdout, c.Stdout()); err != nil && stdout.overflow {
			overflow <- struct{}{}
		}
	}()
	go func() { defer readers.Done(); io.Copy(stderr, c.Stderr()) }()

	lines := make(chan input, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := in.Read(buf)
			if n > 0 {
				lines <- input{line: append([]byte(nil), buf[:n]...)}
				return
			}
			if err == io.EOF {
				lines <- input{eof: true}
				return
			}
			if err != nil {
				lines <- input{err: err}
				return
			}
		}
	}()

	seconds := cfg.EntrySeconds
	if seconds == 0 {
		seconds = cfg.HoldSeconds
	}
	timer := time.NewTimer(time.Duration(seconds) * time.Second)
	// stop: end the exact child; release only when its exit is PROVEN
	stop := func(name string, code int, why error) int {
		if !c.Terminate() {
			ev(event{Event: "unknown", PID: &pid, CreationFILETIME: &birth,
				Problem: strp(sanitize(fmt.Sprintf("%v; the entry's termination could not be proven", why)))})
			return 6 // custody unknown: the caller must not treat the command as ended
		}
		keep.closeAll()
		ev(event{Event: name, PID: &pid, CreationFILETIME: &birth, Problem: problem(why)})
		return code
	}
	select {
	case exitCode := <-c.Exited():
		done := make(chan struct{})
		go func() { readers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second): // an inherited pipe kept open by a descendant
		}
		select {
		case <-overflow:
			keep.closeAll()
			ev(event{Event: "refused", PID: &pid, Problem: strp("entry output exceeds 64 KiB")})
			return 2
		default:
		}
		data := stdout.buf.Bytes()
		b64, n, tail := base64.StdEncoding.EncodeToString(data), len(data), stderr.buf.String()
		ev(event{Event: "exited", PID: &pid, CreationFILETIME: &birth, ExitCode: &exitCode, StdoutBase64: &b64,
			StdoutBytes: &n, StderrTail: &tail})
		keep.closeAll()
		ev(event{Event: "released"})
		return 0
	case <-overflow:
		return stop("refused", 2, errors.New("entry output exceeds 64 KiB"))
	case <-timer.C:
		return stop("timeout", 5, errors.New("the entry did not finish before --entry-timeout"))
	case item := <-lines:
		if item.eof {
			return stop("closed", 4, errors.New("controller closed stdin; the entry was ended"))
		}
		return stop("refused", 2, errors.New("no input is accepted while the verifier owns the entry"))
	}
}
