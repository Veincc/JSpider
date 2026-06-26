package fileutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to a sibling temp file, syncs it, and renames it
// into place so readers never observe a partial file.
func WriteFileAtomic(filename string, data []byte, mode os.FileMode) error {
	file, err := os.CreateTemp(filepath.Dir(filename), "."+filepath.Base(filename)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary output %s: %w", filename, err)
	}
	tempName := file.Name()
	defer os.Remove(tempName)

	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return fmt.Errorf("set output permissions %s: %w", filename, err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write output %s: %w", filename, err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync output %s: %w", filename, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close output %s: %w", filename, err)
	}
	if err := os.Rename(tempName, filename); err != nil {
		return fmt.Errorf("replace output %s: %w", filename, err)
	}
	return nil
}
