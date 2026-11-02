// Package backup creates, checks, and restores tar.gz archives of the data
// directory in pure Go so the scratch container image needs no external tools.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Limits against decompression bombs. Variables so tests stay fast.
var (
	MaxFileSize  int64 = 64 << 20
	MaxTotalSize int64 = 1 << 30
	MaxEntries         = 100000
)

var required = []string{"vault/identity.age", "vault/recipient.txt", "state.json"}

// A fresh server creates these before anyone can restore.
var startupFiles = map[string]bool{".keep": true, "gate.token": true}

// Create writes a gzipped tar archive of regular files under dataDir.
func Create(w io.Writer, dataDir string) error {
	dataDir = filepath.Clean(dataDir)
	fi, err := os.Lstat(dataDir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return errors.New("data directory is not a directory")
	}
	gw := gzip.NewWriter(w)
	tw := tar.NewWriter(gw)

	walkErr := filepath.WalkDir(dataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == dataDir {
			return nil
		}
		rel, err := filepath.Rel(dataDir, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		if strings.HasSuffix(d.Name(), ".tmp") || name == "gate.token" || d.Name() == "gate.token" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		typ := d.Type()
		if typ&os.ModeSymlink != 0 || d.IsDir() || !typ.IsRegular() {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		// Read the whole file first so a concurrent size change cannot corrupt the tar stream.
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name,
			Size:     int64(len(data)),
			Mode:     0o600,
			ModTime:  info.ModTime().UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
	if walkErr != nil {
		tw.Close()
		gw.Close()
		return walkErr
	}
	if err := tw.Close(); err != nil {
		gw.Close()
		return err
	}
	return gw.Close()
}

// Check verifies that r is a valid backup containing required vault and state files.
func Check(r io.Reader) (int, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return 0, err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	var count int
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}
		name, err := validateHeader(hdr, total)
		if err != nil {
			return 0, err
		}
		n, err := io.Copy(io.Discard, io.LimitReader(tr, MaxFileSize+1))
		if err != nil {
			return 0, err
		}
		if n > MaxFileSize {
			return 0, fmt.Errorf("file %q exceeds size limit", name)
		}
		total += n
		if total > MaxTotalSize {
			return 0, errors.New("backup exceeds total size limit")
		}
		count++
		if count > MaxEntries {
			return 0, errors.New("backup has too many entries")
		}
		if hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA {
			seen[name] = true
		}
	}
	if err := checkRequired(seen); err != nil {
		return 0, err
	}
	return count, nil
}

func checkRequired(seen map[string]bool) error {
	for _, req := range required {
		if !seen[req] {
			return fmt.Errorf("backup missing %s", req)
		}
	}
	return nil
}

// Restore extracts a backup into dataDir if dataDir does not exist, is empty, or
// holds only files a fresh server creates. Nothing changes unless the whole
// archive is valid.
func Restore(r io.Reader, dataDir string) error {
	dataDir = filepath.Clean(dataDir)
	existed := false
	if fi, err := os.Lstat(dataDir); err == nil {
		if !fi.IsDir() {
			return errors.New("restore target is not a directory")
		}
		ents, err := os.ReadDir(dataDir)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if !startupFiles[e.Name()] {
				return errors.New("restore target directory is not empty")
			}
		}
		existed = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// Inside the target when it exists: in a container the data directory is a
	// mounted volume and its parent is read-only.
	parent := filepath.Dir(dataDir)
	if existed {
		parent = dataDir
	} else if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	tmpDir, err := os.MkdirTemp(parent, ".ucr-restore-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		return err
	}

	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var total int64
	count, seen := 0, map[string]bool{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		name, err := validateHeader(hdr, total)
		if err != nil {
			return err
		}
		if count++; count > MaxEntries {
			return errors.New("backup has too many entries")
		}
		if hdr.Typeflag != tar.TypeDir {
			seen[name] = true
		}
		target := filepath.Join(tmpDir, filepath.FromSlash(name))
		rel, err := filepath.Rel(tmpDir, target)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("invalid archive path %q", hdr.Name)
		}
		if hdr.Typeflag == tar.TypeDir {
			if err := mkdirAll0700(tmpDir, target); err != nil {
				return err
			}
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, MaxFileSize+1))
		if err != nil {
			return err
		}
		if int64(len(data)) > MaxFileSize {
			return fmt.Errorf("file %q exceeds size limit", name)
		}
		total += int64(len(data))
		if total > MaxTotalSize {
			return errors.New("backup exceeds total size limit")
		}
		if err := mkdirAll0700(tmpDir, filepath.Dir(target)); err != nil {
			return err
		}
		if err := os.WriteFile(target, data, 0o600); err != nil {
			return err
		}
		if err := os.Chmod(target, 0o600); err != nil {
			return err
		}
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if err := checkRequired(seen); err != nil {
		return err
	}

	if !existed {
		return os.Rename(tmpDir, dataDir)
	}
	return moveDirContents(tmpDir, dataDir)
}

func validateHeader(hdr *tar.Header, total int64) (string, error) {
	if hdr.Linkname != "" {
		return "", fmt.Errorf("links are not allowed: %q", hdr.Name)
	}
	switch hdr.Typeflag {
	case tar.TypeReg, tar.TypeRegA, tar.TypeDir:
	default:
		return "", fmt.Errorf("unsupported entry type %d for %q", hdr.Typeflag, hdr.Name)
	}
	raw := hdr.Name
	if raw == "" || strings.Contains(raw, "\\") || strings.ContainsRune(raw, 0) || strings.HasPrefix(raw, "/") || filepath.IsAbs(raw) {
		return "", fmt.Errorf("invalid archive path %q", raw)
	}
	clean := strings.TrimSuffix(raw, "/")
	if clean == "" {
		return "", fmt.Errorf("invalid archive path %q", raw)
	}
	for _, seg := range strings.Split(clean, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("invalid archive path %q", raw)
		}
	}
	if !fs.ValidPath(clean) {
		return "", fmt.Errorf("invalid archive path %q", raw)
	}
	if hdr.Size < 0 || hdr.Size > MaxFileSize {
		return "", fmt.Errorf("file %q exceeds size limit (%d bytes)", raw, hdr.Size)
	}
	if hdr.Typeflag == tar.TypeDir && hdr.Size != 0 {
		return "", fmt.Errorf("directory %q has non-zero size", raw)
	}
	if total+hdr.Size > MaxTotalSize {
		return "", errors.New("backup exceeds total size limit")
	}
	return clean, nil
}

func mkdirAll0700(root, dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." {
		return err
	}
	cur := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		if err := os.Chmod(cur, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func moveDirContents(srcDir, dstDir string) error {
	ents, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		s := filepath.Join(srcDir, e.Name())
		d := filepath.Join(dstDir, e.Name())
		if err := os.Rename(s, d); err != nil {
			if err := copyTree(s, d); err != nil {
				return err
			}
		}
	}
	return nil
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			return os.Chmod(target, 0o700)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, data, 0o600); err != nil {
			return err
		}
		return os.Chmod(target, 0o600)
	})
}
