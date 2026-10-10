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
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
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
	c.Elevated = token.IsElevated()
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
		p, err := windows.KnownFolderPath(f.id, 0)
		if err != nil {
			return c, errors.New("cannot measure a known folder")
		}
		*f.dst = p
	}
	return c, nil
}
