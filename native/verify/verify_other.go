//go:build !windows

package main

import "errors"

// The verifier is Windows-only; these stubs keep the protocol package and its
// tests buildable everywhere.

type fileID struct{ volume, high, low uint32 }

type held struct{ entry *fileID }

func (h *held) closeAll() {}

func currentSID() (string, error) { return "", errors.New("Windows-only") }

func verifyOne(q request, roots []root, owner string, keep *held) (result, *fileID, error) {
	return result{}, nil, errors.New("Windows-only")
}

func processImageIdentity(pid int) (fileID, error) { return fileID{}, errors.New("Windows-only") }

func spawnHeldEntry(cfg config, keep *held) (child, error) { return nil, errors.New("Windows-only") }

func measureContext() (nativeContext, error) { return nativeContext{}, errors.New("Windows-only") }
