package main

import "testing"

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
		Requests: []request{{"document", `C:\x\managed-runtime\authority.json`}}}
	if _, err := validate(base); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(c *config){
		"no op":     func(c *config) { c.OperationID = "" },
		"no roots":  func(c *config) { c.PrivateRoots = nil },
		"overlap":   func(c *config) { c.ResourceRoots = []string{`C:\x`} },
		"dup":       func(c *config) { c.Requests = append(c.Requests, c.Requests[0]) },
		"kind":      func(c *config) { c.Requests = []request{{"frob", `C:\x\managed-runtime\a`}} },
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
