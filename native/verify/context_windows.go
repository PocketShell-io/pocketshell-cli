//go:build windows

package main

import (
	"errors"

	"golang.org/x/sys/windows"
)

// measureContext reads the token and the system folders natively; it never
// consults environment variables.
func measureContext() (nativeContext, error) {
	var c nativeContext
	// TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE: SHGetKnownFolderPath
	// with an explicit user token needs query + impersonate access
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE|windows.TOKEN_DUPLICATE, &token); err != nil {
		return c, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return c, err
	}
	c.OwnerSID = user.User.Sid.String()
	var session uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session); err != nil {
		return c, err
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
	root, err := windows.GetSystemWindowsDirectory()
	if err != nil || len(root) < 3 {
		return c, errors.New("cannot measure the Windows directory")
	}
	c.Windows.SystemRoot, c.Windows.SystemDrive = root, root[:2]
	for _, f := range []struct {
		id  *windows.KNOWNFOLDERID
		dst *string
	}{{windows.FOLDERID_ProgramData, &c.Windows.ProgramData}, {windows.FOLDERID_Profile, &c.Windows.USERPROFILE},
		{windows.FOLDERID_LocalAppData, &c.Windows.LOCALAPPDATA}} {
		// resolved for THIS user's token (its own profile environment), so an
		// empty process environment cannot change or break the measurement
		p, err := token.KnownFolderPath(f.id, 0)
		if err != nil {
			return c, errors.New("cannot measure a known folder")
		}
		*f.dst = p
	}
	return c, nil
}
