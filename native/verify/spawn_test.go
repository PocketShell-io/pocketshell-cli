package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// --- v4.2 final bootstrap bridge: the VERIFIER creates the entry from the held file ----

type fakeChild struct {
	pid        int
	out, errs  string
	exit       chan exitResult
	terminated bool
	termOK     bool
}

func (c *fakeChild) PID() int                  { return c.pid }
func (c *fakeChild) Birth() string             { return "133000000000000001" }
func (c *fakeChild) Stdout() io.Reader         { return strings.NewReader(c.out) }
func (c *fakeChild) Stderr() io.Reader         { return strings.NewReader(c.errs) }
func (c *fakeChild) Exited() <-chan exitResult { return c.exit }
func (c *fakeChild) Terminate() bool           { c.terminated = true; return c.termOK }
func (c *fakeChild) Resume() error             { return nil }
func (c *fakeChild) ImageMatches() bool        { return true }

func runSpawn(t *testing.T, cfg config, in io.Reader, sp spawner) (int, []map[string]any) {
	t.Helper()
	outR, outW, _ := os.Pipe()
	code := runEntry(cfg, &held{}, in, outW, sp)
	outW.Close()
	data, _ := io.ReadAll(outR)
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("not JSON: %q", line)
		}
		events = append(events, e)
	}
	return code, events
}

func spawnCfg() config {
	return config{OperationID: "o", Hold: true, Entry: `C:\r\pocketshell.exe`, SpawnEntry: true,
		EntryArgs: []string{"gateway", "agent", "status", "--json"}, HoldSeconds: 5, EntrySeconds: 5}
}

func names(ev []map[string]any) []string {
	var out []string
	for _, e := range ev {
		out = append(out, e["event"].(string))
	}
	return out
}

func TestSpawnEntryNaturalExit(t *testing.T) {
	c := &fakeChild{pid: 42, out: `{"state":"stopped"}`, errs: "diag", exit: make(chan exitResult, 1), termOK: true}
	c.exit <- exitResult{code: 4}
	var gotArgs []string
	code, ev := runSpawn(t, spawnCfg(), io.MultiReader(authorized(""), blockingReader{}), func(cfg config) (child, error) {
		gotArgs = cfg.EntryArgs
		return c, nil
	})
	if code != 0 || strings.Join(names(ev), ",") != "launched,exited,released" {
		t.Fatalf("%d %v", code, ev)
	}
	if strings.Join(gotArgs, " ") != "gateway agent status --json" {
		t.Fatalf("argv %v", gotArgs)
	}
	ex := ev[1]
	out, _ := base64.StdEncoding.DecodeString(ex["stdoutBase64"].(string))
	if string(out) != `{"state":"stopped"}` || ex["exitCode"].(float64) != 4 || ex["stderrTail"] != "diag" {
		t.Fatalf("%v", ex)
	}
	if ev[0]["imageMatches"] != true || ev[0]["pid"].(float64) != 42 || ev[0]["creationFILETIME"] != "133000000000000001" {
		t.Fatalf("%v", ev[0])
	}
}

func TestSpawnEntryTimeoutTerminatesTheExactChild(t *testing.T) {
	c := &fakeChild{pid: 7, exit: make(chan exitResult), termOK: true}
	cfg := spawnCfg()
	cfg.EntrySeconds = 1
	start := time.Now()
	code, ev := runSpawn(t, cfg, io.MultiReader(authorized(""), blockingReader{}), func(config) (child, error) { return c, nil })
	if code != 5 || names(ev)[len(ev)-1] != "timeout" || !c.terminated || time.Since(start) > 4*time.Second {
		t.Fatalf("%d %v %v", code, ev, c.terminated)
	}
}

func TestSpawnEntryControllerGoneTerminates(t *testing.T) {
	c := &fakeChild{pid: 8, exit: make(chan exitResult), termOK: true}
	code, ev := runSpawn(t, spawnCfg(), authorized(""), func(config) (child, error) { return c, nil })
	if code != 4 || names(ev)[len(ev)-1] != "closed" || !c.terminated {
		t.Fatalf("%d %v", code, ev)
	}
}

func TestSpawnEntryUnprovenTerminationIsUnknown(t *testing.T) {
	c := &fakeChild{pid: 9, exit: make(chan exitResult), termOK: false}
	code, ev := runSpawn(t, spawnCfg(), authorized(""), func(config) (child, error) { return c, nil })
	last := ev[len(ev)-1]
	if code != 6 || last["event"] != "unknown" || last["pid"].(float64) != 9 || last["creationFILETIME"] == nil {
		t.Fatalf("%d %v", code, ev)
	}
}

func TestSpawnEntryOversizedOutputIsRefused(t *testing.T) {
	c := &fakeChild{pid: 10, out: strings.Repeat("x", maxEntryOutput+1), exit: make(chan exitResult, 1), termOK: true}
	c.exit <- exitResult{code: 0}
	code, ev := runSpawn(t, spawnCfg(), io.MultiReader(authorized(""), blockingReader{}), func(config) (child, error) { return c, nil })
	if code != 2 || names(ev)[len(ev)-1] != "refused" {
		t.Fatalf("%d %v", code, ev)
	}
}

func TestSpawnEntryUntypedSpawnFailureIsNeverAbsence(t *testing.T) {
	code, ev := runSpawn(t, spawnCfg(), authorized(""), func(config) (child, error) {
		return nil, errors.New("something failed")
	})
	if code != 6 || ev[len(ev)-1]["event"] != "unknown" {
		t.Fatalf("%d %v", code, ev)
	}
}

// --- NE1: typed, correlated outcomes between authorize and launched -----------------

func TestNE1NoChildCreatedIsPositiveAbsence(t *testing.T) {
	code, ev := runSpawn(t, spawnCfg(), authorized(""), func(config) (child, error) {
		return nil, &notStartedError{errors.New("CreateProcess: bad exe format")}
	})
	last := ev[len(ev)-1]
	if code != 1 || last["event"] != "not-started" || last["childCreated"] != false || last["operationId"] != "o" ||
		last["pid"] != nil {
		t.Fatalf("%d %v", code, ev)
	}
}

func TestNE1CleanedSuspendedChildIsPositiveAbsenceWithItsIdentity(t *testing.T) {
	code, ev := runSpawn(t, spawnCfg(), authorized(""), func(config) (child, error) {
		return nil, &cleanedError{pid: 31, birth: "133000000000000031", why: errors.New("image mismatch")}
	})
	last := ev[len(ev)-1]
	if code != 1 || last["event"] != "cleaned" || last["pid"].(float64) != 31 ||
		last["creationFILETIME"] != "133000000000000031" || last["phase"] != "suspended" {
		t.Fatalf("%d %v", code, ev)
	}
}

func TestNE1FailedCleanupIsStructuredUnknownWithoutAFabricatedBirth(t *testing.T) {
	code, ev := runSpawn(t, spawnCfg(), authorized(""), func(config) (child, error) {
		return nil, &custodyError{pid: 32, birth: "", phase: "suspended", why: errors.New("terminate denied")}
	})
	last := ev[len(ev)-1]
	if code != 6 || last["event"] != "unknown" || last["pid"].(float64) != 32 || last["phase"] != "suspended" ||
		last["authority"] != "verifier-held-handles" {
		t.Fatalf("%d %v", code, ev)
	}
	if _, present := last["creationFILETIME"]; present {
		t.Fatalf("a birth was fabricated: %v", last)
	}
}

func TestRequestsStdinLine(t *testing.T) {
	cfg := config{OperationID: "o"}
	line := `{"version":2,"operationId":"o","requests":[{"kind":"binary","path":"C:\\r\\a.exe","expect":"` +
		strings.Repeat("a", 64) + `"},{"kind":"directory","path":"C:\\r"}]}` + "\n" + "rest"
	br := bufio.NewReader(strings.NewReader(line))
	if err := readRequests(br, &cfg); err != nil || len(cfg.Requests) != 2 || cfg.Requests[0].Expect == "" {
		t.Fatalf("%v %+v", err, cfg.Requests)
	}
	rest, _ := io.ReadAll(br)
	if string(rest) != "rest" {
		t.Fatalf("the following stdin bytes were lost: %q", rest)
	}
	for _, bad := range []string{
		`{"version":2,"operationId":"x","requests":[]}` + "\n",
		`{"version":2,"operationId":"o","requests":[],"extra":1}` + "\n",
		`{"version":2,"operationId":"o","requests":[]} {}` + "\n",
		"",
	} {
		c := config{OperationID: "o"}
		if err := readRequests(bufio.NewReader(strings.NewReader(bad)), &c); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestSpawnEntryArgsValidation(t *testing.T) {
	c, err := parseArgs([]string{"verify", "--operation-id", "o", "--private-root", `C:\r`,
		"--request", `binary:` + strings.Repeat("a", 64) + `=C:\r\pocketshell.exe`, "--hold", "--entry", `C:\r\pocketshell.exe`, "--spawn-entry",
		"--entry-arg", "gateway", "--entry-arg", "agent", "--entry-timeout", "75"})
	if err != nil || !c.SpawnEntry || strings.Join(c.EntryArgs, " ") != "gateway agent" || c.EntrySeconds != 75 {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := validate(c); err != nil {
		t.Fatal(err)
	}
	bad := c
	bad.Hold = false
	if _, err := validate(bad); err == nil {
		t.Fatal("--spawn-entry without --hold accepted")
	}
	bad = c
	bad.SpawnEntry = false
	if _, err := validate(bad); err == nil {
		t.Fatal("--entry-arg without --spawn-entry accepted")
	}
}

type blockingReader struct{}

func (blockingReader) Read(p []byte) (int, error) { select {} }

// --- d056604 review: NB1, NB3, NB4, BI1 ----------------------------------------------

const authorizeLine = `{"version":2,"operationId":"o","op":"authorize"}` + "\n"

func authorized(rest string) io.Reader { return strings.NewReader(authorizeLine + rest) }

func TestBI1NothingIsCreatedWithoutTheCorrelatedAuthorize(t *testing.T) {
	for name, in := range map[string]io.Reader{
		"eof":       strings.NewReader(""),
		"foreign":   strings.NewReader(`{"version":2,"operationId":"other","op":"authorize"}` + "\n"),
		"malformed": strings.NewReader(`{"version":2,"operationId":"o","op":"authorize","x":1}` + "\n"),
		"wrong op":  strings.NewReader(`{"version":2,"operationId":"o","op":"release"}` + "\n"),
		"version":   strings.NewReader(`{"version":1,"operationId":"o","op":"authorize"}` + "\n"),
	} {
		spawned := false
		code, ev := runSpawn(t, spawnCfg(), in, func(config) (child, error) { spawned = true; return nil, nil })
		if spawned || code == 0 || ev[len(ev)-1]["event"] == "launched" {
			t.Errorf("%s: spawned=%v code=%d %v", name, spawned, code, ev)
		}
	}
}

func TestBI1SpawnModeRequiresExpectedDigests(t *testing.T) {
	cfg := spawnCfg()
	cfg.PrivateRoots = []string{`C:\r`}
	cfg.Requests = []request{{Kind: "binary", Path: `C:\r\pocketshell.exe`}}
	if _, err := validate(cfg); err == nil {
		t.Fatal("a spawn-mode request without an expected digest was accepted")
	}
	cfg.Requests = []request{{Kind: "binary", Path: `C:\r\pocketshell.exe`, Expect: strings.Repeat("a", 64)},
		{Kind: "inventory", Path: `C:\r`, Expect: strings.Repeat("b", 64)}}
	if _, err := validate(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestBI1ExpectedDigestMismatchIsARefusedResult(t *testing.T) {
	r := result{OK: true, SHA256: strp(strings.Repeat("c", 64))}
	if err := checkExpect(request{Kind: "binary", Expect: strings.Repeat("a", 64)}, &r); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	r = result{OK: true, Files: []string{"B.txt", "a.txt"}}
	if err := checkExpect(request{Kind: "inventory", Expect: inventoryDigest([]string{"a.txt", "b.txt"})}, &r); err != nil {
		t.Fatal(err)
	}
	if err := checkExpect(request{Kind: "inventory", Expect: inventoryDigest([]string{"a.txt"})}, &r); err == nil {
		t.Fatal("inventory mismatch accepted")
	}
}

func TestNB1UnprovenCleanupBeforeResumeIsUnknownWithIdentity(t *testing.T) {
	code, ev := runSpawn(t, spawnCfg(), authorized(""), func(config) (child, error) {
		return nil, &custodyError{pid: 77, birth: "133000000000000077", why: errors.New("image mismatch")}
	})
	last := ev[len(ev)-1]
	if code != 6 || last["event"] != "unknown" || last["pid"].(float64) != 77 || last["creationFILETIME"] != "133000000000000077" {
		t.Fatalf("%d %v", code, ev)
	}
}

func TestNB3ExitWaitFailureIsNeverExitedZero(t *testing.T) {
	c := &fakeChild{pid: 11, exit: make(chan exitResult, 1), termOK: true}
	c.exit <- exitResult{err: errors.New("WaitForSingleObject failed")}
	code, ev := runSpawn(t, spawnCfg(), io.MultiReader(authorized(""), blockingReader{}), func(config) (child, error) { return c, nil })
	for _, e := range ev {
		if e["event"] == "exited" || e["event"] == "released" {
			t.Fatalf("synthetic success: %v", ev)
		}
	}
	if code == 0 {
		t.Fatalf("exit 0 after a wait failure: %v", ev)
	}
}

type neverEOF struct {
	data string
	sent bool
}

func (r *neverEOF) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		return copy(p, r.data), nil
	}
	select {}
}

type stuckChild struct{ fakeChild }

func (c *stuckChild) Stdout() io.Reader { return &neverEOF{data: "partial"} }

func TestNB4OutputMustReachTrueEOFBeforeExited(t *testing.T) {
	c := &stuckChild{fakeChild{pid: 12, exit: make(chan exitResult, 1), termOK: true}}
	c.exit <- exitResult{code: 0}
	code, ev := runSpawn(t, spawnCfg(), io.MultiReader(authorized(""), blockingReader{}), func(config) (child, error) { return c, nil })
	for _, e := range ev {
		if e["event"] == "exited" {
			t.Fatalf("exited emitted without EOF on stdout: %v", ev)
		}
	}
	if code == 0 {
		t.Fatalf("%d %v", code, ev)
	}
}
