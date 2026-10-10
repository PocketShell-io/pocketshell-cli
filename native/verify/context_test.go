package main

import (
	"encoding/json"
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
