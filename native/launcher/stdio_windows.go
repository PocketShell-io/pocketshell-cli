//go:build windows

package main

import (
	"errors"
	"os"
	"syscall"
)

var consoleKernel = syscall.NewLazyDLL("kernel32.dll")
var attachParentConsole = consoleKernel.NewProc("AttachConsole")
var consoleCodePage = consoleKernel.NewProc("GetConsoleCP")
var detachConsole = consoleKernel.NewProc("FreeConsole")

func validStream(file *os.File) bool {
	if file == nil || file.Fd() == 0 || syscall.Handle(file.Fd()) == syscall.InvalidHandle {
		return false
	}
	_, err := syscall.GetFileType(syscall.Handle(file.Fd()))
	return err == nil
}

func consoleStream(file *os.File) bool {
	if !validStream(file) {
		return false
	}
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(file.Fd()), &mode) == nil
}

func quietChild(files [3]*os.File) ([3]*os.File, uint32, error) {
	for index, file := range files {
		if validStream(file) {
			continue
		}
		// A GUI parent may supply nonzero INVALID handles. Go duplicates
		// them before CreateProcess and would otherwise never launch Python.
		null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if err != nil {
			return files, createNoWindow, err
		}
		files[index] = null
	}
	return files, createNoWindow, nil
}

// GUI entries never attach a console. The CLI can join an EXISTING parent
// console when it actually has console streams, or when Windows gave this
// GUI-subsystem child no usable stdio at all (the native OpenSSH PTY case).
// A valid inherited pipe/file/NUL is never replaced. Ambiguous partial,
// nonconsole stdio retains the quiet behavior used by background callers.
func childStdio(entry string) ([3]*os.File, uint32, error) {
	files := [3]*os.File{os.Stdin, os.Stdout, os.Stderr}
	if entry != "pocketshell" {
		return quietChild(files)
	}
	anyValid, anyConsole := false, false
	for _, file := range files {
		anyValid = anyValid || validStream(file)
		anyConsole = anyConsole || consoleStream(file)
	}
	if anyValid && !anyConsole {
		return quietChild(files)
	}
	attached := false
	cp, _, _ := consoleCodePage.Call()
	if cp == 0 {
		ok, _, _ := attachParentConsole.Call(0xffffffff) // ATTACH_PARENT_PROCESS, never AllocConsole.
		if ok == 0 {
			return quietChild(files)
		}
		attached = true
	}
	selectors := [3]int{syscall.STD_INPUT_HANDLE, syscall.STD_OUTPUT_HANDLE, syscall.STD_ERROR_HANDLE}
	for index, file := range files {
		if validStream(file) {
			continue
		}
		handle, err := syscall.GetStdHandle(selectors[index])
		var mode uint32
		if err != nil || syscall.GetConsoleMode(handle, &mode) != nil {
			// STARTF_USESTDHANDLES can leave the OS stdio table invalid even
			// after AttachConsole. Open only that EXISTING console's device;
			// no console is ever allocated and valid inherited files stay put.
			device := "CONOUT$"
			if index == 0 {
				device = "CONIN$"
			}
			path, _ := syscall.UTF16PtrFromString(device)
			handle, err = syscall.CreateFile(path, syscall.GENERIC_READ|syscall.GENERIC_WRITE,
				syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
			if err != nil {
				continue
			}
			if syscall.GetConsoleMode(handle, &mode) != nil {
				syscall.CloseHandle(handle)
				continue
			}
		}
		files[index] = os.NewFile(uintptr(handle), "parent-console")
	}
	anyConsole = false
	for _, file := range files {
		anyConsole = anyConsole || consoleStream(file)
	}
	if !anyConsole {
		if attached {
			detachConsole.Call()
		}
		return quietChild(files)
	}
	for _, file := range files {
		if !validStream(file) {
			return files, createNoWindow, errors.New("existing parent console has incomplete stdio")
		}
	}
	return files, 0, nil // Inherit the existing console; never create a new one.
}
