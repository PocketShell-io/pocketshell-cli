// pocketshell.exe: the relocatable CLI entry of the ordinary-v2 release
// closure (agreement §14). It runs, from ITS OWN directory,
//
//	python\python.exe -I -B -m pocketshell <args...>
//
// with the inherited (closed) environment and stdio, and exits with the
// child's exit code. It embeds no path, so its bytes are identical at every
// install location; the interpreter's python312._pth fixes sys.path to the
// catalogued closure (no site, no PATH, no PYTHON* variables: -I).
package main

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
)

func main() {
	self, err := os.Executable()
	if err != nil {
		os.Stderr.WriteString("pocketshell: cannot locate itself\n")
		os.Exit(1)
	}
	python := filepath.Join(filepath.Dir(self), "python", "python.exe")
	cmd := exec.Command(python, append([]string{"-I", "-B", "-m", "pocketshell"}, os.Args[1:]...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
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
