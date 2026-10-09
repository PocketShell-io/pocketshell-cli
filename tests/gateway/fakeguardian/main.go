// Fake endpoint guardian for the Windows `gateway service --with-endpoint`
// CI test ONLY. `--listen 127.0.0.1:PORT`: serves an SSH-2.0 identification
// line on every connection (no key exchange), writes guardian-<pid>.json
// (argv, cwd, pid) next to the exe, and runs until killed. Its manifest is
// accepted only through the test's monkeypatched allow-list.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

func main() {
	listen := ""
	for i := 1; i+1 < len(os.Args); i++ {
		if os.Args[i] == "--listen" {
			listen = os.Args[i+1]
		}
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil || host != "127.0.0.1" {
		fmt.Fprintln(os.Stderr, "fake guardian: --listen 127.0.0.1:PORT required")
		os.Exit(2)
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		os.Exit(3)
	}
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	data, _ := json.Marshal(map[string]interface{}{
		"pid": os.Getpid(), "args": os.Args, "cwd": cwd, "exe": exe,
	})
	name := filepath.Join(filepath.Dir(exe), fmt.Sprintf("guardian-%d.json", os.Getpid()))
	if err := os.WriteFile(name, data, 0o600); err != nil {
		os.Exit(4)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		_, _ = conn.Write([]byte("SSH-2.0-FakeGuardian_1.0\r\n"))
		_ = conn.Close()
	}
}
