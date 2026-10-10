package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// Exit codes: 0 verified (and, with --hold, released; with --spawn-entry, the
// entry exited and its result was reported), 1 refusal (verification, or the
// entry refused before resume), 2 malformed request/hold message or entry
// output over 64 KiB, 4 stdin closed (controller gone; the entry was ended),
// 5 timeout (the entry was ended), 6 the entry's termination could not be
// proven (custody unknown).
func main() {
	if len(os.Args) > 1 && os.Args[1] == "context" {
		os.Exit(runContext(os.Args[1:], os.Stdout, measureContext))
	}
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout))
}

func emit(out *os.File, v any) {
	b, _ := json.Marshal(v)
	out.Write(append(b, '\n'))
}

func run(args []string, in io.Reader, out *os.File) int {
	cfg, err := parseArgs(args)
	refuse := func(code int, problem string) int {
		emit(out, reply{Version: protocolVersion, OperationID: cfg.OperationID, OwnerSID: cfg.OwnerSID,
			OK: false, Results: []result{}, Problem: strp(sanitize(problem))})
		return code
	}
	if err != nil {
		return refuse(2, err.Error())
	}
	if cfg.RequestsStdin {
		if len(cfg.Requests) > 0 {
			return refuse(2, "--requests-stdin excludes --request")
		}
		br := bufio.NewReaderSize(in, 64*1024)
		if err := readRequests(br, &cfg); err != nil {
			return refuse(2, err.Error())
		}
		in = br // the same buffered reader carries authorize / hold messages
	}
	roots, err := validate(cfg)
	if err != nil {
		return refuse(2, err.Error())
	}
	sid, err := currentSID()
	if err != nil || !sidRE.MatchString(cfg.OwnerSID) || sid != cfg.OwnerSID {
		return refuse(1, "--owner-sid is not the measured current user")
	}
	keep := &held{}
	defer keep.closeAll()
	results := make([]result, 0, len(cfg.Requests))
	ok := true
	for i, q := range cfg.Requests {
		r, id, err := verifyOne(q, roots, sid, keep)
		if err == nil {
			err = checkExpect(q, &r) // BI1: natively pinned content
		}
		r.Index, r.Kind, r.Path = i, q.Kind, q.Path
		if err != nil {
			r = result{Index: i, Kind: q.Kind, Path: q.Path, Root: r.Root, Problem: strp(sanitize(err.Error()))}
			ok = false
		} else {
			r.OK = true
			if cfg.Hold && same(q.Path, cfg.Entry) && id != nil {
				keep.entry = id
			}
		}
		results = append(results, r)
	}
	rep := reply{Version: protocolVersion, OperationID: cfg.OperationID, OwnerSID: sid, OK: ok, Results: results}
	if b, _ := json.Marshal(rep); len(b) > maxReply {
		return refuse(1, "the reply would exceed 1 MiB; split the request")
	}
	emit(out, rep)
	if !ok {
		return 1
	}
	if !cfg.Hold {
		return 0
	}
	if cfg.SpawnEntry {
		return runEntry(cfg, keep, in, out, func(c config) (child, error) { return spawnHeldEntry(c, keep) })
	}
	return hold(cfg, keep, in, out)
}

func hold(cfg config, keep *held, in io.Reader, out *os.File) int {
	// Each item is one complete line, or the scanner's TERMINAL status:
	// {eof:true} only for a genuine clean end-of-input; {err} for an
	// over-long line (bufio.ErrTooLong) or a read failure. A closed channel
	// is never interpreted as EOF on its own.
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
	ev := func(name string, pid *int, matches *bool, problem error) {
		e := event{Version: protocolVersion, OperationID: cfg.OperationID, Event: name, PID: pid, ImageMatches: matches}
		if problem != nil {
			e.Problem = strp(sanitize(problem.Error()))
		}
		emit(out, e)
	}
	timer := time.NewTimer(time.Duration(cfg.HoldSeconds) * time.Second)
	for {
		select {
		case <-timer.C:
			keep.closeAll()
			ev("timeout", nil, nil, errors.New("hold timed out; handles released"))
			return 5
		case item := <-lines:
			if item.err != nil {
				keep.closeAll()
				ev("refused", nil, nil, fmt.Errorf("unreadable hold input: %v", item.err))
				return 2
			}
			if item.eof {
				keep.closeAll()
				ev("closed", nil, nil, errors.New("controller closed stdin; handles released"))
				return 4
			}
			m, err := parseMessage(item.line, cfg.OperationID)
			if err != nil {
				keep.closeAll()
				ev("refused", nil, nil, err)
				return 2
			}
			switch m.Op {
			case "spawned":
				id, err := processImageIdentity(m.PID)
				matches := err == nil && keep.entry != nil && id == *keep.entry
				if err == nil && !matches {
					err = errors.New("the process image is not the held, verified entry")
				}
				pid := m.PID
				ev("spawned", &pid, &matches, err)
			case "release":
				// the controller must now close stdin: ANY further data refuses
				return awaitEOF(cfg, keep, lines, timer, ev)
			}
		}
	}
}

// awaitEOF: after `release` the only acceptable input is end-of-file. Then
// the handles are closed and `released` is reported (exit 0). Further data
// is refused (exit 2); the hold timer still applies (exit 5).
func awaitEOF(cfg config, keep *held, lines chan input, timer *time.Timer,
	ev func(string, *int, *bool, error)) int {
	select {
	case <-timer.C:
		keep.closeAll()
		ev("timeout", nil, nil, errors.New("no end-of-input after release; handles released"))
		return 5
	case item := <-lines:
		keep.closeAll()
		switch {
		case item.err != nil:
			ev("refused", nil, nil, fmt.Errorf("unreadable input after release: %v", item.err))
			return 2
		case !item.eof:
			ev("refused", nil, nil, errors.New("data after release"))
			return 2
		}
		ev("released", nil, nil, nil)
		return 0
	}
}

// input is one hold-channel item: a line, or the scanner's terminal status.
type input struct {
	line []byte
	eof  bool
	err  error
}
