package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// --- §16.7 the read-only CONTEXT operation (Fleet section16-main-context) ------------

func TestContextArgs(t *testing.T) {
	if op, err := parseContextArgs([]string{"context", "--operation-id", "ctx-1"}); err != nil || op != "ctx-1" {
		t.Fatalf("%q %v", op, err)
	}
	for _, bad := range [][]string{{"context"}, {"context", "--operation-id", "bad id"},
		{"context", "--operation-id", "x", "--extra"}, {"context", "--operation-id"}} {
		if _, err := parseContextArgs(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func runCtx(t *testing.T, args []string, m contextMeasurer) (int, map[string]any, int) {
	t.Helper()
	r, w, _ := os.Pipe()
	code := runContext(args, w, m)
	w.Close()
	data, _ := io.ReadAll(r)
	var reply map[string]any
	if err := json.Unmarshal(data, &reply); err != nil {
		t.Fatalf("not JSON: %q", data)
	}
	return code, reply, len(data)
}

func TestContextReplyShape(t *testing.T) {
	m := func() (nativeContext, error) {
		return nativeContext{OwnerSID: "S-1-5-21-1-2-3-1001", Session: 1, Elevated: false,
			Windows: windowsBindings{SystemDrive: "C:", SystemRoot: `C:\Windows`, ProgramData: `C:\ProgramData`,
				USERPROFILE: `C:\Users\u`, LOCALAPPDATA: `C:\Users\u\AppData\Local`}}, nil
	}
	code, reply, n := runCtx(t, []string{"context", "--operation-id", "ctx-1"}, m)
	if code != 0 || n > 8192 {
		t.Fatalf("%d %d", code, n)
	}
	keys := []string{}
	for k := range reply {
		keys = append(keys, k)
	}
	want := "elevated,operationId,ownerSid,session,version,windows"
	if got := strings.Join(sortStrings(keys), ","); got != want {
		t.Fatalf("keys %s", got)
	}
	win := reply["windows"].(map[string]any)
	if len(win) != 5 || win["SystemRoot"] != `C:\Windows` || reply["elevated"] != false || reply["session"].(float64) != 1 {
		t.Fatalf("%v", reply)
	}
}

func TestContextRefusesElevatedOrUnmeasurable(t *testing.T) {
	elevated := func() (nativeContext, error) {
		return nativeContext{OwnerSID: "S-1-5-21-1-2-3-1001", Session: 1, Elevated: true}, nil
	}
	if code, reply, _ := runCtx(t, []string{"context", "--operation-id", "c"}, elevated); code != 1 || reply["ok"] != false {
		t.Fatalf("elevated accepted: %d %v", code, reply)
	}
	session0 := func() (nativeContext, error) {
		return nativeContext{OwnerSID: "S-1-5-21-1-2-3-1001", Session: 0}, nil
	}
	if code, _, _ := runCtx(t, []string{"context", "--operation-id", "c"}, session0); code != 1 {
		t.Fatal("session 0 accepted")
	}
}

// --- CTX1: elevation is MEASURED with an error-returning call; unknown is never false --

func TestElevationFromQuery(t *testing.T) {
	cases := []struct {
		name     string
		query    func(buf []byte) (uint32, error)
		elevated bool
		ok       bool
	}{
		{"call failed", func([]byte) (uint32, error) { return 0, errors.New("access denied") }, false, false},
		{"short result", func(b []byte) (uint32, error) { return 2, nil }, false, false},
		{"long result", func(b []byte) (uint32, error) { return 8, nil }, false, false},
		{"known zero", func(b []byte) (uint32, error) { b[0], b[1], b[2], b[3] = 0, 0, 0, 0; return 4, nil }, false, true},
		{"non-zero", func(b []byte) (uint32, error) { b[0] = 1; return 4, nil }, true, true},
	}
	for _, c := range cases {
		got, err := elevationFrom(c.query)
		if (err == nil) != c.ok || (c.ok && got != c.elevated) {
			t.Errorf("%s: %v %v", c.name, got, err)
		}
	}
}

func TestContextMeasurementErrorIsNeverSuccess(t *testing.T) {
	failing := func() (nativeContext, error) { return nativeContext{}, errors.New("TokenElevation unmeasurable") }
	if code, reply, _ := runCtx(t, []string{"context", "--operation-id", "c"}, failing); code != 1 || reply["ok"] != false {
		t.Fatalf("%d %v", code, reply)
	}
}

// --- run 38014193268: ProgramData came back UNEXPANDED ("%SystemDrive%\ProgramData") --

func TestExpandMeasured(t *testing.T) {
	vars := map[string]string{"SYSTEMDRIVE": "C:", "SYSTEMROOT": `C:\Windows`, "USERPROFILE": `C:\Users\u`}
	for in, want := range map[string]string{
		`%SystemDrive%\ProgramData`:   `C:\ProgramData`,
		`%USERPROFILE%\AppData\Local`: `C:\Users\u\AppData\Local`,
		`C:\Users\u\AppData\Local`:    `C:\Users\u\AppData\Local`,
		`%systemroot%\..\x`:           `C:\Windows\..\x`, // expansion only; the validator refuses '..'
	} {
		got, err := expandMeasured(in, vars)
		if err != nil || got != want {
			t.Errorf("%q -> %q %v", in, got, err)
		}
	}
	for _, bad := range []string{`%ALLUSERSPROFILE%\x`, `%SystemDrive\x`, `%%\x`} {
		if _, err := expandMeasured(bad, vars); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestPathClassNamesTheProblemWithoutTheValue(t *testing.T) {
	for in, want := range map[string]string{
		"":                  "empty",
		`%SystemDrive%\x`:   "unexpanded",
		`relative\x`:        "relative",
		`C:`:                "drive-only",
		`C:\x\`:             "trailing-separator",
		`C:\Users\RUNNER~1`: "short-name",
		`\\?\C:\x`:          "extended-prefix",
		`\\server\share`:    "unc",
	} {
		if got := pathClass(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
