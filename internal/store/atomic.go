package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"solo-0014-zone-rollout-control/internal/domain"
)

// Normalize applies the same nil-map and schema defaults the running service
// relies on when it loads a snapshot. It is exported so the offline recovery
// command validates and canonicalizes snapshots without starting the service.
func Normalize(state domain.State) domain.State {
	return normalize(state)
}

// EncodeSnapshot renders a state value in the exact on-disk form used by the
// running service, including the trailing newline.
func EncodeSnapshot(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode snapshot: %w", err)
	}
	return append(encoded, '\n'), nil
}

// ReplacePayload atomically replaces path with the provided pre-encoded
// payload. When rename fails the original file is left in place.
func ReplacePayload(path string, payload []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create snapshot directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".pending-*")
	if err != nil {
		return fmt.Errorf("create pending snapshot: %w", err)
	}
	tempPath := temp.Name()
	remove := func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}
	if err := temp.Chmod(mode); err != nil {
		remove()
		return fmt.Errorf("set pending snapshot mode: %w", err)
	}
	if _, err := temp.Write(payload); err != nil {
		remove()
		return fmt.Errorf("write pending snapshot: %w", err)
	}
	if err := temp.Sync(); err != nil {
		remove()
		return fmt.Errorf("sync pending snapshot: %w", err)
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("close pending snapshot: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("replace snapshot: %w", err)
	}
	if directory, err := os.Open(filepath.Dir(path)); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func replaceFile(path string, value any) error {
	encoded, err := EncodeSnapshot(value)
	if err != nil {
		return err
	}
	return ReplacePayload(path, encoded, 0o600)
}
