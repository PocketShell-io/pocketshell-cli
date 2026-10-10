package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"testing/iotest"
)

func TestAbsoluteMirrorsTheSchema(t *testing.T) {
	good := []string{`C:\Users\owner\AppData\Roaming\PocketShell`, `D:/a/b.json`, `C:\a\con2\x.json`}
	bad := []string{`C:\a\..\b`, `C:\a\.\b`, `C:\a:stream`, `C:\a\b.`, `C:\a\b `, `\\server\share\x`,
		`\\?\C:\x`, `C:\a\CON`, `C:\a\nul.txt`, `C:\a\\b`, `a\b`, `C:a\b`, `C:\a\b*`, `C:\`}
	for _, p := range good {
		if !absolute(p) {
			t.Errorf("refused %q", p)
		}
	}
	for _, p := range bad {
		if absolute(p) {
			t.Errorf("accepted %q", p)
		}
	}
}

func TestRelative(t *testing.T) {
	for _, p := range []string{"pocketshell.exe", "python/Lib/site-packages/a.py", "a/con2/b"} {
		if !relative(p) {
			t.Errorf("refused %q", p)
		}
	}
	for _, p := range []string{"../x", "a/../b", "./a", "a/CON", "a/nul.txt", "a.", "a:b", "a//b", "/a", `a\b`} {
		if relative(p) {
			t.Errorf("accepted %q", p)
		}
	}
}

func TestValidate(t *testing.T) {
	base := config{OperationID: "op", PrivateRoots: []string{`C:\x\managed-runtime`},
		Requests: []request{{Kind: "document", Path: `C:\x\managed-runtime\authority.json`}}}
	if _, err := validate(base); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(c *config){
		"no op":     func(c *config) { c.OperationID = "" },
		"no roots":  func(c *config) { c.PrivateRoots = nil },
		"overlap":   func(c *config) { c.ResourceRoots = []string{`C:\x`} },
		"dup":       func(c *config) { c.Requests = append(c.Requests, c.Requests[0]) },
		"kind":      func(c *config) { c.Requests = []request{{Kind: "frob", Path: `C:\x\managed-runtime\a`}} },
		"none":      func(c *config) { c.Requests = nil },
		"hold":      func(c *config) { c.Hold = true },
		"entryOnly": func(c *config) { c.Entry = `C:\x\managed-runtime\a.exe` },
	}
	for name, mutate := range cases {
		c := base
		c.Requests = append([]request(nil), base.Requests...)
		mutate(&c)
		if _, err := validate(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseArgsKeepsOrder(t *testing.T) {
	c, err := parseArgs([]string{"verify", "--operation-id", "o", "--owner-sid", "S-1-5-21-1-2-3-4",
		"--private-root", `C:\r`, "--request", `binary=C:\r\a.exe`, "--request", `document=C:\r\b.json`,
		"--hold", "--entry", `C:\r\a.exe`, "--hold-timeout", "5"})
	if err != nil || len(c.Requests) != 2 || c.Requests[0].Kind != "binary" || !c.Hold || c.HoldSeconds != 5 {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := parseArgs([]string{"verify", "--hold-timeout", "0"}); err == nil {
		t.Fatal("accepted timeout 0")
	}
}

func TestHoldMessages(t *testing.T) {
	if m, err := parseMessage([]byte(`{"op":"spawned","operationId":"o","pid":42}`), "o"); err != nil || m.PID != 42 {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"op":"spawned","operationId":"x","pid":1}`, `{"op":"spawned","operationId":"o"}`,
		`{"op":"kill","operationId":"o"}`, `{"op":"release","operationId":"o","extra":1}`, `nope`} {
		if _, err := parseMessage([]byte(bad), "o"); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// --- N1: ACE header/type/size validated BEFORE any SID decoding -------------------------

func ace(typ byte, mask uint32, sid []byte, extra int) []byte {
	size := 8 + len(sid) + extra
	b := []byte{typ, 0, byte(size), byte(size >> 8), byte(mask), byte(mask >> 8), byte(mask >> 16), byte(mask >> 24)}
	b = append(b, sid...)
	return append(b, make([]byte, extra)...)
}

// S-1-5-21-1-2-3-1001
var userSID = []byte{1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xE9, 3, 0, 0}

func TestDecodeACE(t *testing.T) {
	a, err := decodeACE(ace(0, 0x1F01FF, userSID, 0))
	if err != nil || a.typ != 0 || a.mask != 0x1F01FF || a.sid != "S-1-5-21-1-2-3-1001" {
		t.Fatalf("%+v %v", a, err)
	}
	if a, err := decodeACE(ace(1, 1, userSID, 0)); err != nil || a.typ != 1 {
		t.Fatalf("deny: %+v %v", a, err)
	}
	bad := map[string][]byte{
		"object allowed (5)":   ace(5, 1, userSID, 0),
		"object denied (6)":    ace(6, 1, userSID, 0),
		"callback allowed (9)": ace(9, 1, userSID, 0),
		"audit (2)":            ace(2, 1, userSID, 0),
		"short header":         {0, 0, 4},
		"size mismatch":        append(ace(0, 1, userSID, 0), 0),
		"sid overflows ace":    ace(0, 1, userSID[:20], 0),
		"bad revision":         ace(0, 1, append([]byte{2}, userSID[1:]...), 0),
		"too many subauths":    ace(0, 1, append([]byte{1, 16}, userSID[2:]...), 0),
		"padding > 3":          ace(0, 1, userSID, 4),
	}
	for name, b := range bad {
		if _, err := decodeACE(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// --- N3: exactly one JSON value per message; EOF required after release --------------

func TestHoldMessageTrailingPayload(t *testing.T) {
	for _, bad := range []string{
		`{"op":"release","operationId":"o"}{"op":"release","operationId":"o"}`,
		`{"op":"release","operationId":"o"} x`,
		`{"op":"spawned","operationId":"o","pid":4} {"op":"release","operationId":"o"}`,
	} {
		if _, err := parseMessage([]byte(bad), "o"); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if _, err := parseMessage([]byte(`{"op":"release","operationId":"o"}  `), "o"); err != nil {
		t.Errorf("trailing whitespace refused: %v", err)
	}
}

func holdRun(t *testing.T, input string) (int, []map[string]any) {
	t.Helper()
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	go func() { inW.Write([]byte(input)); inW.Close() }()
	code := hold(config{OperationID: "o", HoldSeconds: 5}, &held{}, inR, outW)
	outW.Close()
	data, _ := io.ReadAll(outR)
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var e map[string]any
		json.Unmarshal([]byte(line), &e)
		events = append(events, e)
	}
	return code, events
}

func TestReleaseRequiresEOF(t *testing.T) {
	code, ev := holdRun(t, `{"op":"release","operationId":"o"}`+"\n")
	if code != 0 || ev[len(ev)-1]["event"] != "released" {
		t.Fatalf("release+EOF: %d %v", code, ev)
	}
	code, ev = holdRun(t, `{"op":"release","operationId":"o"}`+"\n"+`{"op":"release","operationId":"o"}`+"\n")
	if code != 2 || ev[len(ev)-1]["event"] != "refused" {
		t.Fatalf("data after release: %d %v", code, ev)
	}
}

// --- dd792b5 review R1: scanner errors after release are NOT end-of-input -------------

func holdRunReader(t *testing.T, in io.Reader) (int, []map[string]any) {
	t.Helper()
	outR, outW, _ := os.Pipe()
	code := hold(config{OperationID: "o", HoldSeconds: 5}, &held{}, in, outW)
	outW.Close()
	data, _ := io.ReadAll(outR)
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var e map[string]any
		json.Unmarshal([]byte(line), &e)
		events = append(events, e)
	}
	return code, events
}

func TestOversizedLineAfterReleaseIsRefused(t *testing.T) {
	in := `{"op":"release","operationId":"o"}` + "\n" + strings.Repeat("x", 5000) + "\n"
	code, ev := holdRunReader(t, strings.NewReader(in))
	if code != 2 || ev[len(ev)-1]["event"] != "refused" {
		t.Fatalf("oversized after release: %d %v", code, ev)
	}
}

func TestReadErrorAfterReleaseIsRefused(t *testing.T) {
	in := io.MultiReader(strings.NewReader(`{"op":"release","operationId":"o"}`+"\n"),
		iotest.ErrReader(errors.New("pipe broken")))
	code, ev := holdRunReader(t, in)
	if code != 2 || ev[len(ev)-1]["event"] != "refused" {
		t.Fatalf("read error after release: %d %v", code, ev)
	}
}

func TestOversizedLineWhileHeldIsRefused(t *testing.T) {
	code, ev := holdRunReader(t, strings.NewReader(strings.Repeat("y", 5000)+"\n"))
	if code != 2 || ev[len(ev)-1]["event"] != "refused" {
		t.Fatalf("oversized while held: %d %v", code, ev)
	}
}

func TestShortReleaseThenRealEOFIsReleased(t *testing.T) {
	code, ev := holdRunReader(t, strings.NewReader(`{"op":"release","operationId":"o"}`+"\n"))
	if code != 0 || ev[len(ev)-1]["event"] != "released" {
		t.Fatalf("release+EOF: %d %v", code, ev)
	}
}
