// Fake `pocketshell-link` for the Windows `gateway service` CI test ONLY.
//
// It speaks just enough of the real helper's CLI for the service code:
//
//	version --json            the frozen metadata line
//	show --config-dir DIR     non-secret fields, exit 1 unless DIR holds
//	                          config.json + device_ed25519.pem (existence
//	                          only; contents are never read)
//	run --config-dir DIR      writes run-<pid>.json (argv, cwd, pid) NEXT TO
//	                          THE EXE — never into DIR — then idles until
//	                          killed, like the real foreground agent.
//
// Its sha256 is only ever accepted through the test's monkeypatched
// allow-list; the product never trusts it.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func configDir(args []string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--config-dir" {
			return args[i+1]
		}
	}
	return ""
}

func enrolled(dir string) bool {
	for _, name := range []string{"config.json", "device_ed25519.pem"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || !info.Mode().IsRegular() {
			return false
		}
	}
	return dir != ""
}

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(`{"version":"fake","protocol":"pocketshell-tunnel-v1","commit":"fake"}`)
	case "show":
		dir := configDir(os.Args[2:])
		if !enrolled(dir) {
			fmt.Fprintln(os.Stderr, "fake: not enrolled")
			os.Exit(1)
		}
		// The dummy config.json of the test may name the local sshd and its
		// pinned host key (as the real enrollment does); defaults otherwise.
		cfg := struct {
			SSHHost    string `json:"ssh_host"`
			SSHHostKey string `json:"ssh_host_key"`
		}{SSHHost: "127.0.0.1:22"}
		if data, err := os.ReadFile(filepath.Join(dir, "config.json")); err == nil {
			_ = json.Unmarshal(data, &cfg)
		}
		fmt.Println("server:          wss://gateway.invalid")
		fmt.Println("device id:       win-service-e2e")
		fmt.Printf("local ssh:       %s (loopback only)\n", cfg.SSHHost)
		fmt.Println("device key:      SHA256:fake")
		if cfg.SSHHostKey != "" {
			fmt.Printf("pinned ssh host key: %s\n", cfg.SSHHostKey)
		}
	case "run":
		exe, err := os.Executable()
		if err != nil {
			os.Exit(3)
		}
		cwd, _ := os.Getwd()
		marker := map[string]interface{}{
			"pid": os.Getpid(), "args": os.Args, "cwd": cwd, "exe": exe,
			"enrolled": enrolled(configDir(os.Args[2:])),
		}
		data, _ := json.Marshal(marker)
		name := filepath.Join(filepath.Dir(exe), fmt.Sprintf("run-%d.json", os.Getpid()))
		if err := os.WriteFile(name, data, 0o600); err != nil {
			os.Exit(4)
		}
		for {
			time.Sleep(time.Hour)
		}
	default:
		os.Exit(2)
	}
}
