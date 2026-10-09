//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	ancestorMutation = 0x500D0150 // the guardian's ancestor mask (path_authority)
	fullControl      = 0x1F01FF
	attrDirectory    = 0x10
	attrReparse      = 0x400
	accessDirectory  = 0x20081 // FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL
	accessFile       = 0x80020000
	sePDACLProtected = 0x1000
)

// held keeps every verified handle open until release (or process exit).
type held struct {
	handles []windows.Handle
	entry   *fileID
}

type fileID struct {
	volume uint32
	high   uint32
	low    uint32
}

func (h *held) keep(x windows.Handle) { h.handles = append(h.handles, x) }

func (h *held) closeAll() {
	for i := len(h.handles) - 1; i >= 0; i-- {
		windows.CloseHandle(h.handles[i])
	}
	h.handles = nil
}

func currentSID() (string, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}

func open(path string, access uint32, share uint32, directory bool) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	} else {
		flags |= windows.FILE_FLAG_SEQUENTIAL_SCAN
	}
	h, err := windows.CreateFile(p, access, share, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return 0, fmt.Errorf("cannot open %s: %v", path, err)
	}
	return h, nil
}

func info(h windows.Handle) (windows.ByHandleFileInformation, error) {
	var d windows.ByHandleFileInformation
	err := windows.GetFileInformationByHandle(h, &d)
	return d, err
}

func identity(d windows.ByHandleFileInformation) fileID {
	return fileID{d.VolumeSerialNumber, d.FileIndexHigh, d.FileIndexLow}
}

// checkShape: no reparse point, the expected type, single link for files.
func checkShape(h windows.Handle, path string, directory bool) (windows.ByHandleFileInformation, error) {
	d, err := info(h)
	if err != nil {
		return d, fmt.Errorf("cannot inspect %s", path)
	}
	if d.FileAttributes&attrReparse != 0 || (d.FileAttributes&attrDirectory != 0) != directory {
		return d, fmt.Errorf("refusing reparse point or unexpected file type: %s", path)
	}
	if !directory && d.NumberOfLinks != 1 {
		return d, fmt.Errorf("refusing multiply-linked file: %s", path)
	}
	return d, nil
}

type aces struct {
	owner     string
	protected bool
	entries   []aceEntry
	nullDACL  bool
}

func security(h windows.Handle) (aces, error) {
	var out aces
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return out, err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return out, errors.New("no owner")
	}
	out.owner = owner.String()
	control, _, err := sd.Control()
	if err != nil {
		return out, err
	}
	out.protected = control&sePDACLProtected != 0
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		out.nullDACL = true
		return out, nil
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		// GetAce bounds the ACE inside the ACL; read ONLY its header first,
		// then hand exactly AceSize bytes to the validating decoder.
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return out, err
		}
		header := (*[4]byte)(unsafe.Pointer(ace))
		size := int(header[2]) | int(header[3])<<8
		if size < 4 {
			return out, errors.New("truncated ACE")
		}
		entry, err := decodeACE(unsafe.Slice((*byte)(unsafe.Pointer(ace)), size))
		if err != nil {
			return out, err
		}
		out.entries = append(out.entries, entry)
	}
	return out, nil
}

// checkPrivate mirrors pocketshell.windows_security._check(private=True).
func checkPrivate(h windows.Handle, path, owner string) error {
	s, err := security(h)
	if err != nil {
		return fmt.Errorf("refusing the security of %s: %v", path, err)
	}
	if s.owner != owner || s.nullDACL {
		return fmt.Errorf("private storage must be owned by you with a non-null DACL: %s", path)
	}
	if !s.protected {
		return fmt.Errorf("private storage DACL must disable inheritance: %s", path)
	}
	full := false
	for _, a := range s.entries {
		if a.typ != 0 || a.flags&8 != 0 || a.sid != owner {
			return fmt.Errorf("private storage DACL grants access outside your account: %s", path)
		}
		full = full || a.mask&fullControl == fullControl
	}
	if !full {
		return fmt.Errorf("private storage requires current-user full control: %s", path)
	}
	return nil
}

// checkAncestor mirrors WindowsApi._validate_security(role="ancestor").
func checkAncestor(h windows.Handle, path, owner string) error {
	s, err := security(h)
	if err != nil {
		return fmt.Errorf("refusing the security of %s: %v", path, err)
	}
	trusted := map[string]bool{owner: true, "S-1-5-18": true, "S-1-5-32-544": true, trustedInstaller: true}
	if !trusted[s.owner] {
		return fmt.Errorf("%s owner %s has no ancestor authority", path, s.owner)
	}
	if s.nullDACL {
		return fmt.Errorf("%s has a NULL DACL", path)
	}
	for _, a := range s.entries {
		if a.typ != 0 && a.typ != 1 {
			return fmt.Errorf("%s has an unsupported ACE type", path)
		}
		if a.typ != 0 || a.flags&8 != 0 || trusted[a.sid] {
			continue
		}
		if a.mask&ancestorMutation != 0 {
			return fmt.Errorf("%s: %s holds foreign mutation authority (mask 0x%08X)", path, a.sid, a.mask)
		}
	}
	return nil
}

// chain opens every directory from the drive root down to dir (inclusive),
// without delete sharing (pinned against rename/delete), refuses reparse
// points, applies the owner-only private shape to EVERY directory at or
// below privateRoot (the declared root and all intermediates), and the
// guardian ancestor authority to every other directory except `object`.
func chain(dir, object, owner, privateRoot string, keep *held) error {
	clean := strings.ReplaceAll(dir, "/", `\`)
	parts := strings.Split(clean[3:], `\`)
	current := clean[:3]
	paths := []string{current}
	for _, p := range parts {
		if p == "" {
			continue
		}
		current = strings.TrimSuffix(current, `\`) + `\` + p
		paths = append(paths, current)
	}
	for _, p := range paths {
		h, err := open(p, accessDirectory, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, true)
		if err != nil {
			return err
		}
		keep.keep(h)
		if _, err := checkShape(h, p, true); err != nil {
			return err
		}
		if privateRoot != "" && under(p, privateRoot) {
			if err := checkPrivate(h, p, owner); err != nil {
				return err
			}
		} else if !same(p, object) {
			if err := checkAncestor(h, p, owner); err != nil {
				return err
			}
		}
	}
	return nil
}

func finalPath(h windows.Handle) (string, error) {
	buf := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
	if err != nil || n == 0 || int(n) >= len(buf) {
		return "", errors.New("cannot resolve the opened path")
	}
	s := windows.UTF16ToString(buf[:n])
	return strings.TrimPrefix(s, `\\?\`), nil
}

func parent(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	i := strings.LastIndex(p, `\`)
	if i <= 2 {
		return p[:3]
	}
	return p[:i]
}

func verifyFile(path, owner, privateRoot string, document bool, keep *held) (result, *fileID, error) {
	var r result
	private := privateRoot != ""
	if err := chain(parent(path), path, owner, privateRoot, keep); err != nil {
		return r, nil, err
	}
	h, err := open(path, accessFile, windows.FILE_SHARE_READ, false)
	if err != nil {
		return r, nil, err
	}
	keep.keep(h)
	d, err := checkShape(h, path, false)
	if err != nil {
		return r, nil, err
	}
	if private {
		if err := checkPrivate(h, path, owner); err != nil {
			return r, nil, err
		}
	}
	canonical, err := finalPath(h)
	if err != nil {
		return r, nil, err
	}
	if !same(canonical, path) {
		return r, nil, errors.New("the opened object is not the requested path")
	}
	hash := sha256.New()
	var body []byte
	var size int64
	buf := make([]byte, 1<<20)
	for {
		var n uint32
		if err := windows.ReadFile(h, buf, &n, nil); err != nil {
			return r, nil, fmt.Errorf("cannot read %s", path)
		}
		if n == 0 {
			break
		}
		size += int64(n)
		if size > maxFile {
			return r, nil, errors.New("file larger than 256 MiB")
		}
		hash.Write(buf[:n])
		if document && size <= maxDocument {
			body = append(body, buf[:n]...)
		}
	}
	if document && size > maxDocument {
		return r, nil, errors.New("document larger than 64 KiB")
	}
	sum := hex.EncodeToString(hash.Sum(nil))
	r.CanonicalPath, r.Size, r.SHA256 = &canonical, &size, &sum
	if document {
		b := base64.StdEncoding.EncodeToString(body)
		r.BytesBase64 = &b
	}
	id := identity(d)
	return r, &id, nil
}

func entryIdentity(path string) (fileID, error) {
	h, err := open(path, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, false)
	if err != nil {
		return fileID{}, err
	}
	defer windows.CloseHandle(h)
	d, err := info(h)
	if err != nil {
		return fileID{}, err
	}
	return identity(d), nil
}

func verifyDirectory(path, owner, privateRoot string, keep *held) (result, error) {
	var r result
	if err := chain(path, path, owner, privateRoot, keep); err != nil {
		return r, err
	}
	h := keep.handles[len(keep.handles)-1]
	canonical, err := finalPath(h)
	if err != nil {
		return r, err
	}
	if !same(canonical, path) {
		return r, errors.New("the opened directory is not the requested path")
	}
	r.CanonicalPath = &canonical
	return r, nil
}

func verifyInventory(path, owner, privateRoot string, keep *held) (result, error) {
	var r result
	private := privateRoot != ""
	if err := chain(path, path, owner, privateRoot, keep); err != nil {
		return r, err
	}
	files := []string{}
	var walk func(dir, rel string) error
	walk = func(dir, rel string) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("cannot list %s", dir)
		}
		for _, e := range entries {
			full := dir + `\` + e.Name()
			name := e.Name()
			if rel != "" {
				name = rel + "/" + e.Name()
			}
			fi, err := e.Info()
			if err != nil {
				return fmt.Errorf("cannot inspect %s", full)
			}
			if fi.Mode()&os.ModeSymlink != 0 || fi.Mode()&os.ModeIrregular != 0 {
				return fmt.Errorf("%s is a reparse point", full)
			}
			directory := e.IsDir()
			access, share := uint32(accessFile), uint32(windows.FILE_SHARE_READ)
			if directory {
				access, share = accessDirectory, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE
			}
			h, err := open(full, access, share, directory)
			if err != nil {
				return err
			}
			keep.keep(h)
			if _, err := checkShape(h, full, directory); err != nil {
				return err
			}
			if private {
				if err := checkPrivate(h, full, owner); err != nil {
					return err
				}
			}
			if directory {
				if err := walk(full, name); err != nil {
					return err
				}
			} else {
				files = append(files, name)
				if len(files) > maxInventory {
					return errors.New("more than 4096 files")
				}
			}
		}
		return nil
	}
	if err := walk(strings.TrimSuffix(strings.ReplaceAll(path, "/", `\`), `\`), ""); err != nil {
		return r, err
	}
	r.Files = files
	return r, nil
}

func verifyOne(q request, roots []root, owner string, keep *held) (result, *fileID, error) {
	if !absolute(q.Path) {
		return result{}, nil, errors.New("not a plain drive-absolute path")
	}
	rt, err := ownerOf(q.Path, roots)
	if err != nil {
		return result{}, nil, err
	}
	var r result
	var id *fileID
	privateRoot := ""
	if rt.Private {
		privateRoot = rt.Path
	}
	switch q.Kind {
	case "document":
		if !strings.HasSuffix(strings.ToLower(q.Path), ".json") {
			return result{Root: &rt.Path}, nil, errors.New("only .json documents return bytes; use binary")
		}
		r, id, err = verifyFile(q.Path, owner, privateRoot, true, keep)
	case "binary":
		r, id, err = verifyFile(q.Path, owner, privateRoot, false, keep)
	case "directory":
		r, err = verifyDirectory(q.Path, owner, privateRoot, keep)
	case "inventory":
		r, err = verifyInventory(q.Path, owner, privateRoot, keep)
	}
	r.Root = &rt.Path
	return r, id, err
}

// processImageIdentity: the file identity of a live process's kernel image.
func processImageIdentity(pid int) (fileID, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return fileID{}, fmt.Errorf("cannot open process %d: %v", pid, err)
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return fileID{}, fmt.Errorf("cannot read the image of process %d", pid)
	}
	return entryIdentity(windows.UTF16ToString(buf[:n]))
}
