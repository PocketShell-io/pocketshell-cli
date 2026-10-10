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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
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
	digestRE    = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

var kinds = map[string]bool{"document": true, "binary": true, "directory": true, "inventory": true,
	"system-reference": true}

// systemReferences: the ONLY measured system references (agreement §16.13):
// the guardian 6cf servicing roles, below the natively measured system
// directory (GetSystemWindowsDirectory + \System32). Nothing else outside the
// declared roots is ever accepted.
var systemReferences = map[string]bool{"cmd.exe": true, "conhost.exe": true}

// systemReferenceMatch: p must be EXACTLY <system32>\<allowed name> (case-
// insensitive, plain backslashes; no 8.3, \\?\, dot segments, trailing dot,
// SysWOW64 or other directory).
func systemReferenceMatch(p, system32 string) error {
	if !absolute(p) || strings.Contains(p, "/") || strings.Contains(p, "~") {
		return errors.New("a system reference must be a plain canonical drive path")
	}
	i := strings.LastIndex(p, `\`)
	if i < 0 || !systemReferences[strings.ToLower(p[i+1:])] {
		return errors.New("not an allowed system reference (cmd.exe, conhost.exe)")
	}
	if !strings.EqualFold(p[:i], system32) {
		return errors.New("a system reference must live directly in the measured system directory")
	}
	return nil
}

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
	Kind   string
	Path   string
	Expect string // expected sha256 (binary/document) or inventoryDigest (inventory); "" = none
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
	SpawnEntry    bool     // v4.2: the verifier itself creates the entry from the held file
	EntryArgs     []string // the entry's argv after its path, ordered
	EntrySeconds  int      // the entry's deadline (default: the hold timeout)
	RequestsStdin bool     // the ordered requests arrive as the FIRST stdin line (no command-line limit)
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
			head, path, ok := strings.Cut(v, "=")
			if !ok {
				return cfg, usageError{"--request is KIND[:SHA256]=PATH"}
			}
			kind, expect, _ := strings.Cut(head, ":")
			cfg.Requests = append(cfg.Requests, request{Kind: kind, Path: path, Expect: expect})
		case "--entry":
			v, err = value(&i, args[i])
			cfg.Entry = v
		case "--hold":
			cfg.Hold = true
		case "--spawn-entry":
			cfg.SpawnEntry = true
		case "--requests-stdin":
			cfg.RequestsStdin = true
		case "--entry-arg":
			v, err = value(&i, args[i])
			cfg.EntryArgs = append(cfg.EntryArgs, v)
		case "--entry-timeout":
			v, err = value(&i, args[i])
			if err == nil {
				if _, e := fmt.Sscanf(v, "%d", &cfg.EntrySeconds); e != nil || cfg.EntrySeconds < 1 || cfg.EntrySeconds > maxHold {
					return cfg, usageError{fmt.Sprintf("--entry-timeout must be 1..%d seconds", maxHold)}
				}
			}
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
		if q.Expect != "" && (q.Kind == "directory" || !digestRE.MatchString(q.Expect)) {
			return nil, usageError{"an expected digest is 64 lowercase hex, for document/binary/inventory only"}
		}
		if q.Kind == "system-reference" {
			name := q.Path[strings.LastIndex(q.Path, `\`)+1:]
			if q.Expect == "" || !absolute(q.Path) || strings.Contains(q.Path, "/") || !systemReferences[strings.ToLower(name)] {
				return nil, usageError{"a system-reference is cmd.exe/conhost.exe with an expected digest"}
			}
			for _, r := range roots {
				if under(q.Path, r.Path) {
					return nil, usageError{"a system-reference is never inside a declared root"}
				}
			}
		}
		// BI1: nothing may execute unless EVERY content request is natively pinned
		if cfg.SpawnEntry && q.Kind != "directory" && q.Expect == "" {
			return nil, usageError{"--spawn-entry needs an expected digest on every document/binary/inventory request"}
		}
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
	if cfg.SpawnEntry && !cfg.Hold {
		return nil, usageError{"--spawn-entry needs --hold --entry"}
	}
	if !cfg.SpawnEntry && (len(cfg.EntryArgs) > 0 || cfg.EntrySeconds != 0) {
		return nil, usageError{"--entry-arg/--entry-timeout are only meaningful with --spawn-entry"}
	}
	total := 0
	for _, a := range cfg.EntryArgs {
		total += len(a)
		if strings.ContainsRune(a, 0) {
			return nil, usageError{"--entry-arg contains NUL"}
		}
	}
	if len(cfg.EntryArgs) > 64 || total > 8192 {
		return nil, usageError{"entry argv too long"}
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
	Version          int     `json:"version"`
	OperationID      string  `json:"operationId"`
	Event            string  `json:"event"`
	PID              *int    `json:"pid,omitempty"`
	CreationFILETIME *string `json:"creationFILETIME,omitempty"`
	ImageMatches     *bool   `json:"imageMatches,omitempty"`
	ExitCode         *int    `json:"exitCode,omitempty"`
	StdoutBase64     *string `json:"stdoutBase64,omitempty"`
	StdoutBytes      *int    `json:"stdoutBytes,omitempty"`
	StderrTail       *string `json:"stderrTail,omitempty"`
	Phase            string  `json:"phase,omitempty"`
	Authority        string  `json:"authority,omitempty"`
	ChildCreated     *bool   `json:"childCreated,omitempty"`
	Problem          *string `json:"problem"`
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
	// exactly ONE JSON value per line: trailing values or data are refused
	if rest := strings.TrimSpace(string(line[dec.InputOffset():])); rest != "" {
		return m, errors.New("trailing data after the hold message")
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

// --- N1: ACE decoding with header/type/size validated BEFORE the SID ------------------

type aceEntry struct {
	typ   byte
	flags byte
	mask  uint32
	sid   string
}

// decodeACE validates one raw ACE (exactly AceSize bytes): only
// ACCESS_ALLOWED (0) and ACCESS_DENIED (1) are supported — object, callback,
// audit and every other type is refused before any SID is read. The SID must
// be revision 1, at most 15 sub-authorities, and lie inside the ACE (padding
// of at most 3 bytes).
func decodeACE(b []byte) (aceEntry, error) {
	if len(b) < 4 {
		return aceEntry{}, errors.New("truncated ACE header")
	}
	typ, flags, size := b[0], b[1], int(b[2])|int(b[3])<<8
	if size != len(b) {
		return aceEntry{}, errors.New("ACE size does not match its bytes")
	}
	if typ != 0 && typ != 1 {
		return aceEntry{}, fmt.Errorf("unsupported ACE type %d", typ)
	}
	if size < 8+8 {
		return aceEntry{}, errors.New("ACE too small for a SID")
	}
	mask := uint32(b[4]) | uint32(b[5])<<8 | uint32(b[6])<<16 | uint32(b[7])<<24
	sid := b[8:]
	if sid[0] != 1 || sid[1] > 15 {
		return aceEntry{}, errors.New("malformed SID in ACE")
	}
	sidLen := 8 + 4*int(sid[1])
	if sidLen > len(sid) || len(sid)-sidLen > 3 {
		return aceEntry{}, errors.New("SID does not fit its ACE")
	}
	var authority uint64
	for _, x := range sid[2:8] {
		authority = authority<<8 | uint64(x)
	}
	text := fmt.Sprintf("S-1-%d", authority)
	if authority >= 1<<32 {
		text = fmt.Sprintf("S-1-0x%012X", authority)
	}
	for i := 0; i < int(sid[1]); i++ {
		o := 8 + 4*i
		text += fmt.Sprintf("-%d", uint32(sid[o])|uint32(sid[o+1])<<8|uint32(sid[o+2])<<16|uint32(sid[o+3])<<24)
	}
	return aceEntry{typ: typ, flags: flags, mask: mask, sid: text}, nil
}

// inventoryDigest is the expected-digest form of an inventory: sha256 of the
// lower-cased relative paths, sorted, joined by "\n".
func inventoryDigest(files []string) string {
	lower := make([]string, len(files))
	for i, f := range files {
		lower[i] = strings.ToLower(f)
	}
	sort.Strings(lower)
	sum := sha256.Sum256([]byte(strings.Join(lower, "\n")))
	return hex.EncodeToString(sum[:])
}

// checkExpect refuses a verified result whose content is not the expected one.
func checkExpect(q request, r *result) error {
	if q.Expect == "" {
		return nil
	}
	switch q.Kind {
	case "binary", "document", "system-reference":
		if r.SHA256 == nil || *r.SHA256 != q.Expect {
			return errors.New("sha256 is not the expected digest")
		}
	case "inventory":
		if inventoryDigest(r.Files) != q.Expect {
			return errors.New("the inventory is not the expected closure")
		}
	}
	return nil
}

// parseAuthorize: exactly {"version":2,"operationId":OP,"op":"authorize"}.
func parseAuthorize(line []byte, operationID string) error {
	var m struct {
		Version     int    `json:"version"`
		OperationID string `json:"operationId"`
		Op          string `json:"op"`
	}
	dec := json.NewDecoder(strings.NewReader(string(line)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return errors.New("malformed authorize message")
	}
	if rest := strings.TrimSpace(string(line[dec.InputOffset():])); rest != "" {
		return errors.New("trailing data after the authorize message")
	}
	if m.Version != protocolVersion || m.Op != "authorize" || m.OperationID != operationID {
		return errors.New("not the correlated authorize for this operation")
	}
	return nil
}

// requestsLine: the --requests-stdin first line.
type requestsLine struct {
	Version     int    `json:"version"`
	OperationID string `json:"operationId"`
	Requests    []struct {
		Kind   string `json:"kind"`
		Path   string `json:"path"`
		Expect string `json:"expect,omitempty"`
	} `json:"requests"`
}

const maxRequestsLine = 1024 * 1024

// readRequests reads and parses the first stdin line (<= 1 MiB, one JSON
// value, the correlated operation) into cfg.Requests.
func readRequests(br interface{ ReadByte() (byte, error) }, cfg *config) error {
	var line []byte
	for {
		b, err := br.ReadByte()
		if err != nil {
			return errors.New("no requests line on stdin")
		}
		if b == '\n' {
			break
		}
		line = append(line, b)
		if len(line) > maxRequestsLine {
			return errors.New("the requests line exceeds 1 MiB")
		}
	}
	var m requestsLine
	dec := json.NewDecoder(strings.NewReader(string(line)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return errors.New("malformed requests line")
	}
	if rest := strings.TrimSpace(string(line[dec.InputOffset():])); rest != "" {
		return errors.New("trailing data after the requests line")
	}
	if m.Version != protocolVersion || m.OperationID != cfg.OperationID {
		return errors.New("the requests line is not for this operation")
	}
	for _, r := range m.Requests {
		cfg.Requests = append(cfg.Requests, request{Kind: r.Kind, Path: r.Path, Expect: r.Expect})
	}
	return nil
}

// aclRole: which ACL policy applies to directory p on the chain to `object`
// inside the declared request `root` (diagnostic 7a). Directories ABOVE the
// root get NO ACL authority check — they are still opened, held without delete
// sharing, refused if reparse, and canonical-path checked — because their
// ACLs belong to the user's profile (e.g. AppData's capability-SID ACEs), and
// holding them pins the root against rename/replace. At or below the root:
// "private" (owner-only, protected) for a private root, "ancestor" (no foreign
// mutation authority) for a resources root; the object itself is checked by
// its leaf policy.
func aclRole(p, object, root string, private bool) string {
	switch {
	case !under(p, root):
		return "none"
	case private:
		return "private"
	case same(p, object):
		return "object"
	}
	return "ancestor"
}
