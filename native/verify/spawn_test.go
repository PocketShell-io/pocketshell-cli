package main

import (
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
	exit       chan int
	terminated bool
	termOK     bool
}

func (c *fakeChild) PID() int           { return c.pid }
func (c *fakeChild) Birth() string      { return "133000000000000001" }
func (c *fakeChild) Stdout() io.Reader  { return strings.NewReader(c.out) }
func (c *fakeChild) Stderr() io.Reader  { return strings.NewReader(c.errs) }
func (c *fakeChild) Exited() <-chan int { return c.exit }
func (c *fakeChild) Terminate() bool    { c.terminated = true; return c.termOK }
func (c *fakeChild) Resume() error      { return nil }
func (c *fakeChild) ImageMatches() bool { return true }

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
	c := &fakeChild{pid: 42, out: `{"state":"stopped"}`, errs: "diag", exit: make(chan int, 1), termOK: true}
	c.exit <- 4
	var gotArgs []string
	code, ev := runSpawn(t, spawnCfg(), strings.NewReader(""), func(cfg config) (child, error) {
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
	if string(out) != `{"state":"stopped"}` || ex["exitCode"].(float64) != 4 || ex["stderrTail"] != "diag" || c.terminated {
		t.Fatalf("%v", ex)
	}
	if ev[0]["imageMatches"] != true || ev[0]["pid"].(float64) != 42 || ev[0]["creationFILETIME"] != "133000000000000001" {
		t.Fatalf("%v", ev[0])
	}
}

func TestSpawnEntryTimeoutTerminatesTheExactChild(t *testing.T) {
	c := &fakeChild{pid: 7, exit: make(chan int), termOK: true}
	cfg := spawnCfg()
	cfg.EntrySeconds = 1
	start := time.Now()
	code, ev := runSpawn(t, cfg, blockingReader{}, func(config) (child, error) { return c, nil })
	if code != 5 || names(ev)[len(ev)-1] != "timeout" || !c.terminated || time.Since(start) > 4*time.Second {
		t.Fatalf("%d %v %v", code, ev, c.terminated)
	}
}

func TestSpawnEntryControllerGoneTerminates(t *testing.T) {
	c := &fakeChild{pid: 8, exit: make(chan int), termOK: true}
	code, ev := runSpawn(t, spawnCfg(), strings.NewReader(""), func(config) (child, error) { return c, nil })
	if code != 4 || names(ev)[len(ev)-1] != "closed" || !c.terminated {
		t.Fatalf("%d %v", code, ev)
	}
}

func TestSpawnEntryUnprovenTerminationIsUnknown(t *testing.T) {
	c := &fakeChild{pid: 9, exit: make(chan int), termOK: false}
	code, ev := runSpawn(t, spawnCfg(), strings.NewReader(""), func(config) (child, error) { return c, nil })
	last := ev[len(ev)-1]
	if code != 6 || last["event"] != "unknown" || last["pid"].(float64) != 9 || last["creationFILETIME"] == nil {
		t.Fatalf("%d %v", code, ev)
	}
}

func TestSpawnEntryOversizedOutputIsRefused(t *testing.T) {
	c := &fakeChild{pid: 10, out: strings.Repeat("x", maxEntryOutput+1), exit: make(chan int, 1), termOK: true}
	c.exit <- 0
	code, ev := runSpawn(t, spawnCfg(), blockingReader{}, func(config) (child, error) { return c, nil })
	if code != 2 || names(ev)[len(ev)-1] != "refused" {
		t.Fatalf("%d %v", code, ev)
	}
}

func TestSpawnEntryRefusedBeforeResumeNeverLaunches(t *testing.T) {
	code, ev := runSpawn(t, spawnCfg(), strings.NewReader(""), func(config) (child, error) {
		return nil, errors.New("the suspended entry's image is not the held, verified file")
	})
	if code != 1 || strings.Join(names(ev), ",") != "refused" {
		t.Fatalf("%d %v", code, ev)
	}
}

func TestSpawnEntryArgsValidation(t *testing.T) {
	c, err := parseArgs([]string{"verify", "--operation-id", "o", "--private-root", `C:\r`,
		"--request", `binary=C:\r\pocketshell.exe`, "--hold", "--entry", `C:\r\pocketshell.exe`, "--spawn-entry",
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
