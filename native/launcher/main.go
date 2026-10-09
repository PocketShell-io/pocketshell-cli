// pocketshell.exe: the relocatable, QUIET CLI entry of the ordinary-v2 release
// closure (agreement §14). It runs, from ITS OWN directory,
//
//	python\python.exe -I -B -m pocketshell <args...>
//
// with the inherited (closed) environment and stdio, and exits with the
// child's exit code. It embeds no path, so its bytes are identical at every
// install location; the interpreter's python312._pth fixes sys.path to the
// catalogued closure (no site, no PATH, no PYTHON* variables: -I).
//
// Quiet (no visible CMD): it is linked as a GUI-subsystem binary
// (-H=windowsgui, so Windows allocates no console for it) and starts the
// console-subsystem interpreter with CREATE_NO_WINDOW, so the child gets no
// console either. stdio still flows through the inherited handles.
//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
)

const createNoWindow = 0x08000000

func main() {
	self, err := os.Executable()
	if err != nil {
		os.Stderr.WriteString("pocketshell: cannot locate itself\n")
		os.Exit(1)
	}
	python := filepath.Join(filepath.Dir(self), "python", "python.exe")
	cmd := exec.Command(python, append([]string{"-I", "-B", "-m", "pocketshell"}, os.Args[1:]...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow, HideWindow: true}
	// Console control events reach the child directly; the launcher only waits.
	signal.Ignore(os.Interrupt)
	err = cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		os.Exit(0)
	case errors.As(err, &exit):
		os.Exit(exit.ExitCode())
	default:
		os.Stderr.WriteString("pocketshell: cannot start the bundled interpreter\n")
		os.Exit(1)
	}
}
