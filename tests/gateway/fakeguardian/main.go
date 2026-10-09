// Fake endpoint guardian + fake daemon for the windows-latest CI test ONLY.
//
// It implements the FINAL guardian ABI (INTERFACE.md, guardian 6cf7ae85) so
// `pocketshell gateway service` can be exercised against the real Task
// Scheduler without the real guardian. Never shipped; not native proof.
//
// As "python.exe -I -S -B <guardian.py> --manifest M [--check-only]":
//   - --check-only: reads the manifest, prints a preflight line, exits 0
//     without any state, generation, Job or daemon;
//   - otherwise holds <state>\INSTANCE.lock exclusively, allocates
//     <state>\generation-<uuidhex> (never reused), starts the daemon
//     (<daemon> -D -f <config>) CREATE_NO_WINDOW in a KILL_ON_JOB_CLOSE Job,
//     records its pid + decimal creation FILETIME, waits for the loopback
//     listener, writes READY.json, THEN atomically replaces
//     <state>\CURRENT.json = {version:1, generation, ready, manifestSHA256};
//   - polls STOP.json: exactly {pid, creationFILETIME, manifestSHA256,
//     stopOwnedJob:true} => terminates its Job, CLOSED.json {accepted,
//     requestedOwnedJobStop, activeAtClose:0, cleanupErrors:[]}, exit 0;
//     anything else (or the daemon dying) => Job terminated,
//     CLOSED.json accepted=false, exit 1 (the scheduler restarts it).
//
// As "<daemon> -D -f <config>" (daemon mode): a real SSH server (key
// exchange with the configured host key, every authentication refused) on
// ListenAddress:Port from the config.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

type manifest struct {
	Owner  string `json:"ownerSID"`
	State  string `json:"state"`
	Config string `json:"config"`
	Port   int    `json:"port"`
	Daemon string `json:"daemon"`
	Root   string `json:"root"`
}

func main() {
	args := os.Args[1:]
	bootstrap := len(args) >= 6 && args[0] == "-I" && args[1] == "-S" && args[2] == "-B" &&
		strings.HasSuffix(strings.ToLower(args[3]), ".py") && args[4] == "--manifest"
	if bootstrap && len(args) == 7 && args[6] == "--check-only" {
		os.Exit(checkOnly(args[5]))
	}
	if bootstrap && len(args) == 6 {
		os.Exit(guardian(args[5], args[3]))
	}
	if len(args) == 3 && args[0] == "-D" && args[1] == "-f" {
		os.Exit(daemon(args[2]))
	}
	fmt.Fprintln(os.Stderr, "fake: usage")
	os.Exit(2)
}

// --- daemon -------------------------------------------------------------------------

func daemon(config string) int {
	data, err := os.ReadFile(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake daemon: config:", err)
		return 3
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			values[strings.ToLower(fields[0])] = strings.Trim(strings.Join(fields[1:], " "), "\"")
		}
	}
	keyBytes, err := os.ReadFile(values["hostkey"])
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake daemon: host key:", err)
		return 4
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake daemon: parse host key:", err)
		return 5
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, errors.New("fake daemon: no authentication")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", net.JoinHostPort(values["listenaddress"], values["port"]))
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake daemon: listen:", err)
		return 6
	}
	fmt.Fprintln(os.Stderr, "fake daemon: listening on", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			_ = c.SetDeadline(time.Now().Add(20 * time.Second))
			if sc, _, _, err := ssh.NewServerConn(c, cfg); err == nil {
				_ = sc.Close()
			}
			_ = c.Close()
		}(conn)
	}
}

// --- guardian -----------------------------------------------------------------------

var (
	user32                   = windows.NewLazySystemDLL("user32.dll")
	procGetProcessWinStation = user32.NewProc("GetProcessWindowStation")
	procGetUserObjectInfo    = user32.NewProc("GetUserObjectInformationW")
	procCreateDesktopW       = user32.NewProc("CreateDesktopW")
)

func objectName(h uintptr) string {
	buf := make([]uint16, 256)
	var needed uint32
	r, _, _ := procGetUserObjectInfo.Call(h, 2, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2), uintptr(unsafe.Pointer(&needed)))
	if r == 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}

// context reports the ACTUAL token/session/station facts, as the real
// guardian's token_context() does, and creates a private desktop on the
// actual station (kept open for the guardian's lifetime).
func context(ownerSID string) (map[string]interface{}, string, error) {
	var session uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session); err != nil {
		return nil, "", err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, "", err
	}
	station, _, _ := procGetProcessWinStation.Call()
	name := objectName(station)
	var flags struct{ Inherit, Reserved, Flags uint32 }
	var needed uint32
	procGetUserObjectInfo.Call(station, 1, uintptr(unsafe.Pointer(&flags)), unsafe.Sizeof(flags), uintptr(unsafe.Pointer(&needed)))
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	desktopName := "PocketShellPrivate_" + hex.EncodeToString(buf)
	dn, _ := windows.UTF16PtrFromString(desktopName)
	desk, _, derr := procCreateDesktopW.Call(uintptr(unsafe.Pointer(dn)), 0, 0, 0, 0x201ff, 0)
	if desk == 0 {
		return nil, "", fmt.Errorf("CreateDesktopW on %s: %v", name, derr)
	}
	ctx := map[string]interface{}{
		"ownerSID": user.User.Sid.String(), "session": session, "station": name,
		"stationVisible": flags.Flags&1 != 0, "desktop": "", "activeConsoleSession": windows.WTSGetActiveConsoleSessionId(),
	}
	return ctx, name + "\\" + desktopName, nil
}

func checkOnly(manifestPath string) int {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return 10
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil || m.State == "" || m.Port == 0 {
		return 11
	}
	sum := sha256.Sum256(raw)
	fmt.Printf("{\"phase\":\"preflight-only\",\"manifestSHA256\":\"%s\",\"daemonSpawned\":false,\"stateAllocated\":false}\n", hex.EncodeToString(sum[:]))
	return 0
}

func filetime(h windows.Handle) (string, error) {
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(h, &c, &e, &k, &u); err != nil {
		return "", err
	}
	return strconv.FormatUint(uint64(c.HighDateTime)<<32|uint64(c.LowDateTime), 10), nil
}

// ownerSID is the manifest owner: every protocol file is created with an
// explicit owner = ownerSID and a protected owner/SYSTEM/Administrators DACL
// (agreement §4), whatever the token's default owner is (an S4U token of an
// administrator defaults to BUILTIN\Administrators).
var ownerSID string

func writeJSON(path string, value interface{}) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(
		"O:" + ownerSID + "D:P(A;;FA;;;" + ownerSID + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	tmp := path + ".tmp"
	name, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, &sa, windows.CREATE_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	var written uint32
	err = windows.WriteFile(h, data, &written, nil)
	_ = windows.CloseHandle(h)
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func listening(port int) bool {
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func guardian(manifestPath, script string) int {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return 10
	}
	scriptBytes, err := os.ReadFile(script)
	if err != nil {
		return 10
	}
	scriptSum := sha256.Sum256(scriptBytes)
	guardianSHA := hex.EncodeToString(scriptSum[:])
	sum := sha256.Sum256(raw)
	manifestSHA := hex.EncodeToString(sum[:])
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil || m.State == "" || m.Port == 0 || m.Owner == "" {
		return 11
	}
	ownerSID = m.Owner
	lockName, _ := windows.UTF16PtrFromString(filepath.Join(m.State, "INSTANCE.lock"))
	lock, err := windows.CreateFile(lockName, windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return 12 // another guardian holds the state
	}
	defer windows.CloseHandle(lock)

	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	genDir := filepath.Join(m.State, "generation-"+hex.EncodeToString(buf))
	if err := os.Mkdir(genDir, 0o700); err != nil {
		return 13 // a fresh generation only; never reuse one
	}
	result := map[string]interface{}{"manifestSHA256": manifestSHA, "accepted": false, "cleanupErrors": []string{}}
	closeWith := func(code int, failure string) int {
		if failure != "" {
			result["failure"] = failure
		}
		_ = writeJSON(filepath.Join(genDir, "CLOSED.json"), result)
		return code
	}
	if listening(m.Port) {
		return closeWith(14, "port occupied")
	}
	ctx, privateDesktop, err := context(ownerSID)
	if err != nil {
		return closeWith(24, err.Error())
	}
	result["context"] = ctx

	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return closeWith(15, "job")
	}
	defer windows.CloseHandle(job)
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return closeWith(16, "job limits")
	}
	cmd := exec.Command(m.Daemon, "-D", "-f", m.Config)
	cmd.Dir = m.Root
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if logFile, err := os.Create(filepath.Join(genDir, "daemon.stderr.log")); err == nil {
		cmd.Stdout, cmd.Stderr = logFile, logFile
		defer logFile.Close()
	}
	if err := cmd.Start(); err != nil {
		return closeWith(17, "daemon start")
	}
	pid := cmd.Process.Pid
	handle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		_ = cmd.Process.Kill()
		return closeWith(18, "daemon handle")
	}
	defer windows.CloseHandle(handle)
	if err := windows.AssignProcessToJobObject(job, handle); err != nil {
		_ = cmd.Process.Kill()
		return closeWith(19, "job assign")
	}
	birth, err := filetime(handle)
	if err != nil {
		return closeWith(20, "daemon birth")
	}
	guardianBirth, _ := filetime(windows.CurrentProcess())
	deadline := time.Now().Add(15 * time.Second)
	for !listening(m.Port) {
		if time.Now().After(deadline) {
			_ = windows.TerminateJobObject(job, 1)
			return closeWith(21, "listener absent")
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = guardianBirth
	ready := map[string]interface{}{
		"accepted": false, "manifestSHA256": manifestSHA, "cleanupErrors": []string{},
		"pid": pid, "creationFILETIME": birth, "guardianPID": os.Getpid(),
		"port": m.Port, "heldProcessHandle": true, "ownedJob": true, "context": ctx,
		"privateDesktop": privateDesktop, "sourceSHA256": guardianSHA,
		"desktopACL": map[string]interface{}{"fake": "CI fake guardian: default desktop security, not the guardian's checked ACL"},
	}
	readyPath := filepath.Join(genDir, "READY.json")
	if err := writeJSON(readyPath, ready); err != nil {
		return closeWith(22, "ready")
	}
	current := map[string]interface{}{
		"version": 1, "generation": genDir, "ready": readyPath, "manifestSHA256": manifestSHA,
	}
	if err := writeJSON(filepath.Join(m.State, "CURRENT.json"), current); err != nil {
		return closeWith(23, "current")
	}
	result["pid"], result["creationFILETIME"] = pid, birth

	stopPath := filepath.Join(genDir, "STOP.json")
	for {
		if ev, _ := windows.WaitForSingleObject(handle, 500); ev == windows.WAIT_OBJECT_0 {
			_ = windows.TerminateJobObject(job, 1)
			return closeWith(1, "held daemon exited unexpectedly")
		}
		data, err := os.ReadFile(stopPath)
		if err != nil {
			continue
		}
		var req map[string]interface{}
		valid := json.Unmarshal(data, &req) == nil && len(req) == 4 &&
			req["pid"] == float64(pid) && req["creationFILETIME"] == birth &&
			req["manifestSHA256"] == manifestSHA && req["stopOwnedJob"] == true
		_ = windows.TerminateJobObject(job, 0)
		_, _ = windows.WaitForSingleObject(handle, 5000)
		for i := 0; i < 50 && listening(m.Port); i++ {
			time.Sleep(100 * time.Millisecond)
		}
		if !valid {
			return closeWith(1, "stop request does not name the exact held identity")
		}
		result["requestedOwnedJobStop"] = true
		result["activeAtClose"] = 0
		result["accepted"] = true
		return closeWith(0, "")
		// (an invalid STOP keeps requestedOwnedJobStop absent, accepted false)
	}
}
