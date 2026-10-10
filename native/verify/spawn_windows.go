//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type winChild struct {
	process, thread windows.Handle
	job             windows.Handle
	pid             int
	birth           string
	stdout, stderr  *os.File
	exited          chan exitResult
}

func (c *winChild) PID() int                  { return c.pid }
func (c *winChild) Birth() string             { return c.birth }
func (c *winChild) Stdout() io.Reader         { return c.stdout }
func (c *winChild) Stderr() io.Reader         { return c.stderr }
func (c *winChild) Exited() <-chan exitResult { return c.exited }

// Terminate ends the WHOLE command tree through the verifier-owned job and
// proves it: the entry process object is signalled AND the job has no active
// process left (the bundled Python included). Broken-away guardian/link
// (BREAKAWAY_OK) are, by design, not members.
func (c *winChild) Terminate() bool {
	return terminateTree(c.job, c.process)
}

type basicAccounting struct {
	TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime int64
	TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses     uint32
}

func activeProcesses(job windows.Handle) (uint32, error) {
	var info basicAccounting
	err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil)
	return info.ActiveProcesses, err
}

func terminateTree(job, process windows.Handle) bool {
	if job != 0 {
		if n, err := activeProcesses(job); err != nil || n > 0 {
			windows.TerminateJobObject(job, 1)
		}
	} else if err := windows.TerminateProcess(process, 1); err != nil {
		var code uint32
		if windows.GetExitCodeProcess(process, &code) != nil || code == 259 {
			return false
		}
	}
	ev, err := windows.WaitForSingleObject(process, 5000)
	if err != nil || ev != windows.WAIT_OBJECT_0 {
		return false
	}
	if job == 0 {
		return true
	}
	for i := 0; i < 50; i++ {
		n, err := activeProcesses(job)
		if err != nil {
			return false
		}
		if n == 0 {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// ownedJob: KILL_ON_JOB_CLOSE (the tree cannot outlive the verifier's custody)
// and BREAKAWAY_OK (the CLI's persistent guardian/link may still break away and
// are then measured job-free by the CLI itself).
func ownedJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
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
		return nil, &notStartedError{errors.New("the entry is not held")}
	}
	outR, outW, err := inheritablePipe()
	if err != nil {
		return nil, &notStartedError{err}
	}
	errR, errW, err := inheritablePipe()
	if err != nil {
		windows.CloseHandle(outR)
		windows.CloseHandle(outW)
		return nil, &notStartedError{err}
	}
	nulName, _ := windows.UTF16PtrFromString("NUL")
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	nul, err := windows.CreateFile(nulName, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		&sa, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		for _, h := range []windows.Handle{outR, outW, errR, errW} {
			windows.CloseHandle(h)
		}
		return nil, &notStartedError{err}
	}
	childEnds := []windows.Handle{nul, outW, errW}
	defer func() {
		for _, h := range childEnds {
			windows.CloseHandle(h)
		}
	}()
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return nil, &notStartedError{err}
	}
	defer attrs.Delete()
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&childEnds[0]),
		uintptr(len(childEnds))*unsafe.Sizeof(childEnds[0])); err != nil {
		return nil, &notStartedError{err}
	}
	si := windows.StartupInfoEx{}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_HIDE
	si.StdInput, si.StdOutput, si.StdErr = nul, outW, errW
	si.ProcThreadAttributeList = attrs.List()
	app, err := windows.UTF16PtrFromString(cfg.Entry)
	if err != nil {
		return nil, &notStartedError{err}
	}
	cmd, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{cfg.Entry}, cfg.EntryArgs...)))
	if err != nil {
		return nil, &notStartedError{err}
	}
	job, err := ownedJob()
	if err != nil {
		windows.CloseHandle(outR)
		windows.CloseHandle(errR)
		return nil, &notStartedError{fmt.Errorf("cannot create the entry's job: %v", err)}
	}
	var pi windows.ProcessInformation
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW | windows.EXTENDED_STARTUPINFO_PRESENT |
		windows.CREATE_UNICODE_ENVIRONMENT)
	if err := windows.CreateProcess(app, cmd, nil, nil, true, flags, nil, nil, &si.StartupInfo, &pi); err != nil {
		windows.CloseHandle(outR)
		windows.CloseHandle(errR)
		windows.CloseHandle(job)
		return nil, &notStartedError{fmt.Errorf("cannot create the entry: %v", err)}
	}
	c := &winChild{process: pi.Process, thread: pi.Thread, job: job, pid: int(pi.ProcessId), exited: make(chan exitResult, 1),
		stdout: os.NewFile(uintptr(outR), "entry-stdout"), stderr: os.NewFile(uintptr(errR), "entry-stderr")}
	refuse := func(why error) (child, error) {
		// the suspended entry is not yet in the job: end it by its own handle
		if !terminateTree(0, pi.Process) {
			// NB1: keep EVERY handle (process, thread, job, pipes) and report the
			// exact identity; custody stays with this process
			keep.retain(pi.Process, pi.Thread, job)
			return nil, &custodyError{pid: c.pid, birth: c.birth, phase: "suspended", why: why}
		}
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
		windows.CloseHandle(job)
		c.stdout.Close()
		c.stderr.Close()
		return nil, &cleanedError{pid: c.pid, birth: c.birth, why: why}
	}
	if b, err := birthOf(pi.Process); err != nil {
		return refuse(errors.New("cannot read the entry's creation time")) // birth stays "" (never fabricated)
	} else {
		c.birth = b
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
	if err := windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		return refuse(fmt.Errorf("cannot place the entry in its owned job: %v", err))
	}
	if r, err := windows.ResumeThread(pi.Thread); err != nil || r == 0xFFFFFFFF {
		if !terminateTree(job, pi.Process) {
			keep.retain(pi.Process, pi.Thread, job)
			return nil, &custodyError{pid: c.pid, birth: c.birth, phase: "resume", why: errors.New("cannot resume the entry")}
		}
		return nil, &cleanedError{pid: c.pid, birth: c.birth, why: errors.New("cannot resume the entry")}
	}
	windows.CloseHandle(pi.Thread)
	keep.retain(job) // KILL_ON_JOB_CLOSE: the job lives exactly as long as the verifier's custody
	go func() {
		ev, err := windows.WaitForSingleObject(pi.Process, windows.INFINITE)
		if err != nil || ev != windows.WAIT_OBJECT_0 {
			c.exited <- exitResult{err: fmt.Errorf("wait failed (%d, %v)", ev, err)}
			return
		}
		var code uint32
		if err := windows.GetExitCodeProcess(pi.Process, &code); err != nil {
			c.exited <- exitResult{err: fmt.Errorf("exit code unreadable: %v", err)}
			return
		}
		c.exited <- exitResult{code: int(code)}
	}()
	return c, nil
}
