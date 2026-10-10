//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

type winChild struct {
	process, thread windows.Handle
	pid             int
	birth           string
	stdout, stderr  *os.File
	exited          chan int
}

func (c *winChild) PID() int           { return c.pid }
func (c *winChild) Birth() string      { return c.birth }
func (c *winChild) Stdout() io.Reader  { return c.stdout }
func (c *winChild) Stderr() io.Reader  { return c.stderr }
func (c *winChild) Exited() <-chan int { return c.exited }
func (c *winChild) Terminate() bool {
	if err := windows.TerminateProcess(c.process, 1); err != nil {
		// already exited is fine: prove it below
		var code uint32
		if windows.GetExitCodeProcess(c.process, &code) != nil || code == 259 {
			return false
		}
	}
	ev, err := windows.WaitForSingleObject(c.process, 5000)
	return err == nil && ev == windows.WAIT_OBJECT_0
}

func birthOf(h windows.Handle) (string, error) {
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(h, &c, &e, &k, &u); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d", uint64(c.HighDateTime)<<32|uint64(c.LowDateTime)), nil
}

func inheritablePipe() (r, w windows.Handle, err error) {
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	if err = windows.CreatePipe(&r, &w, &sa, 0); err != nil {
		return
	}
	// the parent's end must NOT be inherited
	err = windows.SetHandleInformation(r, windows.HANDLE_FLAG_INHERIT, 0)
	return
}

// spawnHeldEntry creates cfg.Entry SUSPENDED (CREATE_NO_WINDOW, the verifier's
// own closed environment, stdin = NUL, stdout/stderr = pipes, ONLY those three
// handles inheritable via PROC_THREAD_ATTRIBUTE_HANDLE_LIST), proves that the
// suspended process's kernel image is the HELD entry file (same volume serial
// and file index as the handle verified and still held), then resumes it.
// On any failure before resume the exact suspended child is terminated
// through its own handle; nothing ran.
func spawnHeldEntry(cfg config, keep *held) (child, error) {
	if keep.entry == nil {
		return nil, errors.New("the entry is not held")
	}
	outR, outW, err := inheritablePipe()
	if err != nil {
		return nil, err
	}
	errR, errW, err := inheritablePipe()
	if err != nil {
		windows.CloseHandle(outR)
		windows.CloseHandle(outW)
		return nil, err
	}
	nulName, _ := windows.UTF16PtrFromString("NUL")
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	nul, err := windows.CreateFile(nulName, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		&sa, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		for _, h := range []windows.Handle{outR, outW, errR, errW} {
			windows.CloseHandle(h)
		}
		return nil, err
	}
	childEnds := []windows.Handle{nul, outW, errW}
	defer func() {
		for _, h := range childEnds {
			windows.CloseHandle(h)
		}
	}()
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return nil, err
	}
	defer attrs.Delete()
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&childEnds[0]),
		uintptr(len(childEnds))*unsafe.Sizeof(childEnds[0])); err != nil {
		return nil, err
	}
	si := windows.StartupInfoEx{}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_HIDE
	si.StdInput, si.StdOutput, si.StdErr = nul, outW, errW
	si.ProcThreadAttributeList = attrs.List()
	app, err := windows.UTF16PtrFromString(cfg.Entry)
	if err != nil {
		return nil, err
	}
	cmd, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{cfg.Entry}, cfg.EntryArgs...)))
	if err != nil {
		return nil, err
	}
	var pi windows.ProcessInformation
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW | windows.EXTENDED_STARTUPINFO_PRESENT |
		windows.CREATE_UNICODE_ENVIRONMENT)
	if err := windows.CreateProcess(app, cmd, nil, nil, true, flags, nil, nil, &si.StartupInfo, &pi); err != nil {
		windows.CloseHandle(outR)
		windows.CloseHandle(errR)
		return nil, fmt.Errorf("cannot create the entry: %v", err)
	}
	c := &winChild{process: pi.Process, thread: pi.Thread, pid: int(pi.ProcessId), exited: make(chan int, 1),
		stdout: os.NewFile(uintptr(outR), "entry-stdout"), stderr: os.NewFile(uintptr(errR), "entry-stderr")}
	refuse := func(why error) (child, error) {
		if !c.Terminate() {
			return nil, fmt.Errorf("%v; and the suspended entry %d could not be proven terminated", why, c.pid)
		}
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
		c.stdout.Close()
		c.stderr.Close()
		return nil, why
	}
	if c.birth, err = birthOf(pi.Process); err != nil {
		return refuse(errors.New("cannot read the entry's creation time"))
	}
	// the suspended process's kernel image must be the held, verified file
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(pi.Process, 0, &buf[0], &n); err != nil {
		return refuse(errors.New("cannot read the entry's kernel image"))
	}
	id, err := entryIdentity(windows.UTF16ToString(buf[:n]))
	if err != nil || id != *keep.entry {
		return refuse(errors.New("the suspended entry's image is not the held, verified file"))
	}
	if r, err := windows.ResumeThread(pi.Thread); err != nil || r == 0xFFFFFFFF {
		return refuse(errors.New("cannot resume the entry"))
	}
	windows.CloseHandle(pi.Thread)
	go func() {
		windows.WaitForSingleObject(pi.Process, windows.INFINITE)
		var code uint32
		windows.GetExitCodeProcess(pi.Process, &code)
		c.exited <- int(code)
	}()
	return c, nil
}
