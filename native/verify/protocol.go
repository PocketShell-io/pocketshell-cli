// pocketshell-verify: the independent bootstrap path verifier
// (user-background-api-agreement v3.1 §11.3/§11.4, verifier protocol v2).
//
// It is a single static Go binary shipped in the Desktop resources and pinned
// by the Desktop release material. It verifies the catalog-pinned runtime
// closure BY HANDLE before the installed CLI/interpreter/modules ever run,
// and (with --hold) keeps every verified handle open — files shared for READ
// only, directories without delete sharing — while Desktop spawns and runs
// the CLI, so no writer, rename or delete can swap a verified file until the
// explicit release.
//
// This file holds the platform-independent protocol: argv, path syntax,
// request/reply shapes and the hold handshake messages.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	protocolVersion = 2
	maxRequests     = 512
	maxDocument     = 64 * 1024
	maxReply        = 1024 * 1024
	maxFile         = 256 * 1024 * 1024
	maxInventory    = 4096
	defaultHold     = 120
	maxHold         = 600
)

var (
	operationRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	sidRE       = regexp.MustCompile(`^S-1-5-21-[0-9]+(-[0-9]+){3}$`)
	driveRE     = regexp.MustCompile(`^[A-Za-z]:[\\/]`)
	deviceRE    = regexp.MustCompile(`(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)`)
	relPartRE   = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

var kinds = map[string]bool{"document": true, "binary": true, "directory": true, "inventory": true}

// component mirrors the Fleet consumer (ManagedVerifierReply.ts) and the
// schema absPath rules for one path component.
func component(x string) bool {
	if x == "" || x == "." || x == ".." || strings.HasSuffix(x, ".") || strings.HasSuffix(x, " ") {
		return false
	}
	for _, c := range x {
		if c < 32 || strings.ContainsRune(`<>:"|?*`, c) {
			return false
		}
	}
	return !deviceRE.MatchString(x)
}

// absolute: drive-absolute only (no UNC, \\?\ or device namespace), no ADS
// colon after the drive, no '.', '..' or empty components, no device names,
// no trailing dot/space aliases, no wildcards or control characters.
func absolute(p string) bool {
	if len(p) > 4096 || len(p) < 4 || !driveRE.MatchString(p) {
		return false
	}
	for _, part := range strings.Split(strings.ReplaceAll(p[3:], "/", `\`), `\`) {
		if !component(part) {
			return false
		}
	}
	return true
}

func relative(p string) bool {
	if len(p) > 1024 {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if !relPartRE.MatchString(part) || !component(part) {
			return false
		}
	}
	return true
}

func norm(p string) string { return strings.ToLower(strings.ReplaceAll(p, "/", `\`)) }

func same(a, b string) bool { return norm(a) == norm(b) }

func under(p, root string) bool {
	np, nr := norm(p), strings.TrimSuffix(norm(root), `\`)
	return np == nr || strings.HasPrefix(np, nr+`\`)
}

type request struct {
	Kind string
	Path string
}

type config struct {
	OperationID   string
	OwnerSID      string
	PrivateRoots  []string
	ResourceRoots []string
	Requests      []request
	Hold          bool
	Entry         string
	HoldSeconds   int
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func parseArgs(args []string) (config, error) {
	cfg := config{HoldSeconds: defaultHold}
	if len(args) == 0 || args[0] != "verify" {
		return cfg, usageError{"usage: pocketshell-verify verify --operation-id ID --owner-sid SID " +
			"[--private-root DIR]... [--resources-root DIR]... --request KIND=PATH... [--hold --entry PATH [--hold-timeout S]]"}
	}
	value := func(i *int, name string) (string, error) {
		if *i+1 >= len(args) {
			return "", usageError{name + " needs a value"}
		}
		*i++
		return args[*i], nil
	}
	for i := 1; i < len(args); i++ {
		var v string
		var err error
		switch args[i] {
		case "--operation-id":
			v, err = value(&i, args[i])
			cfg.OperationID = v
		case "--owner-sid":
			v, err = value(&i, args[i])
			cfg.OwnerSID = v
		case "--private-root":
			v, err = value(&i, args[i])
			cfg.PrivateRoots = append(cfg.PrivateRoots, v)
		case "--resources-root":
			v, err = value(&i, args[i])
			cfg.ResourceRoots = append(cfg.ResourceRoots, v)
		case "--request":
			v, err = value(&i, args[i])
			kind, path, ok := strings.Cut(v, "=")
			if !ok {
				return cfg, usageError{"--request is KIND=PATH"}
			}
			cfg.Requests = append(cfg.Requests, request{kind, path})
		case "--entry":
			v, err = value(&i, args[i])
			cfg.Entry = v
		case "--hold":
			cfg.Hold = true
		case "--hold-timeout":
			v, err = value(&i, args[i])
			if err == nil {
				if _, e := fmt.Sscanf(v, "%d", &cfg.HoldSeconds); e != nil || cfg.HoldSeconds < 1 || cfg.HoldSeconds > maxHold {
					return cfg, usageError{fmt.Sprintf("--hold-timeout must be 1..%d seconds", maxHold)}
				}
			}
		default:
			return cfg, usageError{"unknown argument " + args[i]}
		}
		if err != nil {
			return cfg, err
		}
	}
	return cfg, nil
}

type root struct {
	Path    string
	Private bool
}

// validate returns the declared roots; a usageError is a malformed request (exit 2).
func validate(cfg config) ([]root, error) {
	if !operationRE.MatchString(cfg.OperationID) {
		return nil, usageError{"--operation-id is required ([A-Za-z0-9._-]{1,64})"}
	}
	var roots []root
	for _, r := range cfg.PrivateRoots {
		roots = append(roots, root{r, true})
	}
	for _, r := range cfg.ResourceRoots {
		roots = append(roots, root{r, false})
	}
	if len(roots) == 0 {
		return nil, usageError{"at least one --private-root/--resources-root is required"}
	}
	for i, r := range roots {
		if !absolute(r.Path) {
			return nil, usageError{"declared roots must be plain drive-absolute paths"}
		}
		for _, o := range roots[i+1:] {
			if under(r.Path, o.Path) || under(o.Path, r.Path) {
				return nil, usageError{"declared roots must not overlap"}
			}
		}
	}
	if len(cfg.Requests) == 0 || len(cfg.Requests) > maxRequests {
		return nil, usageError{fmt.Sprintf("1..%d requests are required", maxRequests)}
	}
	seen := map[string]bool{}
	for _, q := range cfg.Requests {
		key := q.Kind + ":" + norm(q.Path)
		if !kinds[q.Kind] || seen[key] {
			return nil, usageError{"unknown or duplicate request"}
		}
		seen[key] = true
	}
	if cfg.Hold {
		found := false
		for _, q := range cfg.Requests {
			if q.Kind == "binary" && same(q.Path, cfg.Entry) {
				found = true
			}
		}
		if !found {
			return nil, usageError{"--hold needs --entry naming one of the binary requests"}
		}
	} else if cfg.Entry != "" {
		return nil, usageError{"--entry is only meaningful with --hold"}
	}
	return roots, nil
}

// ownerOf returns the single declared root containing p.
func ownerOf(p string, roots []root) (root, error) {
	var hits []root
	for _, r := range roots {
		if under(p, r.Path) {
			hits = append(hits, r)
		}
	}
	if len(hits) != 1 {
		return root{}, errors.New("the path is not inside exactly one declared root")
	}
	return hits[0], nil
}

type result struct {
	Index         int      `json:"index"`
	Kind          string   `json:"kind"`
	Path          string   `json:"path"`
	Root          *string  `json:"root"`
	OK            bool     `json:"ok"`
	CanonicalPath *string  `json:"canonicalPath"`
	Size          *int64   `json:"size"`
	SHA256        *string  `json:"sha256"`
	BytesBase64   *string  `json:"bytesBase64"`
	Files         []string `json:"files"`
	Problem       *string  `json:"problem"`
}

type reply struct {
	Version     int      `json:"version"`
	OperationID string   `json:"operationId"`
	OwnerSID    string   `json:"ownerSid"`
	OK          bool     `json:"ok"`
	Results     []result `json:"results"`
	Problem     *string  `json:"problem,omitempty"`
}

// event is a hold-handshake line (never the protocol-v2 reply itself).
type event struct {
	Version      int     `json:"version"`
	OperationID  string  `json:"operationId"`
	Event        string  `json:"event"`
	PID          *int    `json:"pid,omitempty"`
	ImageMatches *bool   `json:"imageMatches,omitempty"`
	Problem      *string `json:"problem"`
}

type message struct {
	Op          string `json:"op"`
	OperationID string `json:"operationId"`
	PID         int    `json:"pid"`
}

func parseMessage(line []byte, operationID string) (message, error) {
	var m message
	dec := json.NewDecoder(strings.NewReader(string(line)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, errors.New("malformed hold message")
	}
	if m.OperationID != operationID {
		return m, errors.New("operationId mismatch")
	}
	switch m.Op {
	case "spawned":
		if m.PID <= 0 {
			return m, errors.New("spawned needs a positive pid")
		}
	case "release":
	default:
		return m, errors.New("unknown op")
	}
	return m, nil
}

func strp(s string) *string { return &s }

func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 {
			return ' '
		}
		return r
	}, s)
	if len(s) > 600 {
		s = s[:600]
	}
	return s
}
