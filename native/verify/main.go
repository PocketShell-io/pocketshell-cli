package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"time"
)

// Exit codes: 0 verified (and, with --hold, released), 1 refusal or image
// mismatch at release, 2 malformed request or hold message, 4 stdin closed
// while holding (the controller is gone), 5 hold timeout.
func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout)) }

func emit(out *os.File, v any) {
	b, _ := json.Marshal(v)
	out.Write(append(b, '\n'))
}

func run(args []string, in *os.File, out *os.File) int {
	cfg, err := parseArgs(args)
	refuse := func(code int, problem string) int {
		emit(out, reply{Version: protocolVersion, OperationID: cfg.OperationID, OwnerSID: cfg.OwnerSID,
			OK: false, Results: []result{}, Problem: strp(sanitize(problem))})
		return code
	}
	if err != nil {
		return refuse(2, err.Error())
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
	return hold(cfg, keep, in, out)
}

func hold(cfg config, keep *held, in *os.File, out *os.File) int {
	lines := make(chan []byte)
	go func() {
		s := bufio.NewScanner(in)
		s.Buffer(make([]byte, 4096), 4096)
		for s.Scan() {
			lines <- append([]byte(nil), s.Bytes()...)
		}
		close(lines)
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
		case line, open := <-lines:
			if !open {
				keep.closeAll()
				ev("closed", nil, nil, errors.New("controller closed stdin; handles released"))
				return 4
			}
			m, err := parseMessage(line, cfg.OperationID)
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
				keep.closeAll()
				ev("released", nil, nil, nil)
				return 0
			}
		}
	}
}
