package main

import (
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"sort"
)

// §16.7 the read-only CONTEXT operation: `pocketshell-verify.exe context
// --operation-id OP`, run by Desktop main with an EMPTY environment and closed
// stdin. Everything is measured NATIVELY (token SID / session / elevation,
// known folders, the Windows directory) — never from the inherited
// environment. One bounded (<= 8 KiB) reply; exit 0. A refusal is
// {version:2, operationId, ok:false, problem}, exit 1 (2 for usage). No caller
// job is rejected: this operation starts nothing.

const maxContextReply = 8 * 1024

var driveOnlyRE = regexp.MustCompile(`^[A-Za-z]:$`)

type windowsBindings struct {
	SystemDrive  string `json:"SystemDrive"`
	SystemRoot   string `json:"SystemRoot"`
	ProgramData  string `json:"ProgramData"`
	USERPROFILE  string `json:"USERPROFILE"`
	LOCALAPPDATA string `json:"LOCALAPPDATA"`
}

type nativeContext struct {
	OwnerSID string
	Session  int
	Elevated bool
	Windows  windowsBindings
}

type contextReply struct {
	Version     int             `json:"version"`
	OperationID string          `json:"operationId"`
	OwnerSID    string          `json:"ownerSid"`
	Session     int             `json:"session"`
	Elevated    bool            `json:"elevated"`
	Windows     windowsBindings `json:"windows"`
}

type contextRefusal struct {
	Version     int    `json:"version"`
	OperationID string `json:"operationId"`
	OK          bool   `json:"ok"`
	Problem     string `json:"problem"`
}

type contextMeasurer func() (nativeContext, error)

func parseContextArgs(args []string) (string, error) {
	if len(args) != 3 || args[0] != "context" || args[1] != "--operation-id" || !operationRE.MatchString(args[2]) {
		return "", usageError{"usage: pocketshell-verify context --operation-id ID"}
	}
	return args[2], nil
}

func runContext(args []string, out *os.File, measure contextMeasurer) int {
	op, err := parseContextArgs(args)
	refuse := func(code int, problem string) int {
		b, _ := json.Marshal(contextRefusal{Version: protocolVersion, OperationID: op, OK: false, Problem: sanitize(problem)})
		out.Write(append(b, '\n'))
		return code
	}
	if err != nil {
		return refuse(2, err.Error())
	}
	c, err := measure()
	if err == nil {
		err = checkContext(c)
	}
	if err != nil {
		return refuse(1, err.Error())
	}
	b, _ := json.Marshal(contextReply{Version: protocolVersion, OperationID: op, OwnerSID: c.OwnerSID,
		Session: c.Session, Elevated: false, Windows: c.Windows})
	if len(b)+1 > maxContextReply {
		return refuse(1, "the context reply would exceed 8 KiB")
	}
	out.Write(append(b, '\n'))
	return 0
}

func checkContext(c nativeContext) error {
	switch {
	case !sidRE.MatchString(c.OwnerSID):
		return errors.New("the token user is not an ordinary account SID")
	case c.Session <= 0:
		return errors.New("not an interactive session (session 0)")
	case c.Elevated:
		return errors.New("the token is elevated; the ordinary-user runtime never runs elevated")
	case !driveOnlyRE.MatchString(c.Windows.SystemDrive):
		return errors.New("SystemDrive is not a drive")
	}
	for _, p := range []string{c.Windows.SystemRoot, c.Windows.ProgramData, c.Windows.USERPROFILE, c.Windows.LOCALAPPDATA} {
		if !absolute(p) {
			return errors.New("a measured folder is not a plain drive-absolute path")
		}
	}
	return nil
}

func sortStrings(s []string) []string { sort.Strings(s); return s }

// elevationFrom reads TokenElevation through an ERROR-RETURNING query: the
// call must succeed and return exactly one DWORD; anything else is a
// measurement error (never "not elevated").
func elevationFrom(query func(buf []byte) (uint32, error)) (bool, error) {
	buf := make([]byte, 4)
	n, err := query(buf)
	if err != nil {
		return false, errors.New("TokenElevation could not be measured")
	}
	if n != 4 {
		return false, errors.New("TokenElevation returned an unexpected length")
	}
	return buf[0]|buf[1]|buf[2]|buf[3] != 0, nil
}
