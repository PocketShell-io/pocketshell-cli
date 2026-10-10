//go:build windows

package main

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// measureContext reads the token and the system folders natively; it never
// consults the process environment (Desktop runs it with an EMPTY one).
//
// Order (deliberate): identity, session and ELEVATION first — an elevated
// token is refused whatever the folders are — then the folders:
//   - SystemRoot/SystemDrive: GetSystemWindowsDirectory;
//   - USERPROFILE: GetUserProfileDirectory(token);
//   - ProgramData, LOCALAPPDATA: the user's DEFAULT environment block built by
//     userenv from the token and the registry (CreateEnvironmentBlock with
//     bInherit=FALSE), never from the inherited environment.
//
// (SHGetKnownFolderPath was measured failing under an empty process
// environment on windows-latest: runs 38012365858 / 38012931234.)
func measureContext() (nativeContext, error) {
	var c nativeContext
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE|windows.TOKEN_DUPLICATE, &token); err != nil {
		return c, fmt.Errorf("cannot open the process token: %v", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return c, fmt.Errorf("cannot read the token user: %v", err)
	}
	c.OwnerSID = user.User.Sid.String()
	var session uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session); err != nil {
		return c, fmt.Errorf("cannot read the session: %v", err)
	}
	c.Session = int(session)
	// CTX1: an error-returning TokenElevation query on the held token
	if c.Elevated, err = elevationFrom(func(buf []byte) (uint32, error) {
		var n uint32
		err := windows.GetTokenInformation(token, windows.TokenElevation, &buf[0], uint32(len(buf)), &n)
		return n, err
	}); err != nil {
		return c, err
	}
	if c.Elevated {
		return c, nil // refused by checkContext; folders are irrelevant
	}
	root, err := windows.GetSystemWindowsDirectory()
	if err != nil || len(root) < 3 {
		return c, errors.New("cannot measure the Windows directory")
	}
	c.Windows.SystemRoot, c.Windows.SystemDrive = root, root[:2]
	if c.Windows.USERPROFILE, err = token.GetUserProfileDirectory(); err != nil {
		return c, fmt.Errorf("cannot measure the user profile directory: %v", err)
	}
	block, err := defaultEnvironment(token) // the user's default block, NOT inherited
	if err != nil {
		return c, fmt.Errorf("cannot build the user's default environment block: %v", err)
	}
	for _, kv := range block {
		name, value, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(name) {
		case "PROGRAMDATA":
			c.Windows.ProgramData = value
		case "LOCALAPPDATA":
			c.Windows.LOCALAPPDATA = value
		}
	}
	if c.Windows.ProgramData == "" || c.Windows.LOCALAPPDATA == "" {
		return c, errors.New("the user's default environment block lacks ProgramData/LOCALAPPDATA")
	}
	return c, nil
}

// defaultEnvironment: CreateEnvironmentBlock(token, bInherit=FALSE) parsed into
// NAME=VALUE strings.
func defaultEnvironment(token windows.Token) ([]string, error) {
	var block *uint16
	if err := windows.CreateEnvironmentBlock(&block, token, false); err != nil {
		return nil, err
	}
	defer windows.DestroyEnvironmentBlock(block)
	var out []string
	var current []uint16
	for i := 0; i < 1<<20; i++ {
		ch := *(*uint16)(unsafe.Add(unsafe.Pointer(block), i*2))
		if ch != 0 {
			current = append(current, ch)
			continue
		}
		if len(current) == 0 {
			break // the terminating empty string
		}
		out = append(out, windows.UTF16ToString(current))
		current = current[:0]
	}
	return out, nil
}
