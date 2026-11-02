package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeSampleDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"vault/identity.age":       "encrypted-identity",
		"vault/recipient.txt":      "age1recipient\n",
		"vault/secrets/github.age": "encrypted-secret",
		"state.json":               `{"version":1}`,
		"audit.jsonl":              `{"event":"init"}` + "\n",
	}
	for rel, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func buildCustomArchive(t *testing.T, fn func(tw *tar.Writer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	fn(tw)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestRoundTrip(t *testing.T) {
	src := makeSampleDataDir(t)

	var buf bytes.Buffer
	if err := Create(&buf, src); err != nil {
		t.Fatalf("Create: %v", err)
	}

	n, err := Check(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if n != 5 {
		t.Fatalf("Check count = %d, want 5", n)
	}

	// Restore into a directory that does not exist yet.
	dst := filepath.Join(t.TempDir(), "restored")
	if err := Restore(bytes.NewReader(buf.Bytes()), dst); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	for _, rel := range []string{"vault/identity.age", "vault/recipient.txt", "vault/secrets/github.age", "state.json", "audit.jsonl"} {
		p := filepath.Join(dst, filepath.FromSlash(rel))
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", rel, err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s perm = %o, want 0600", rel, perm)
		}
	}
	if fi, err := os.Lstat(filepath.Join(dst, "vault")); err != nil {
		t.Fatal(err)
	} else if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Errorf("vault dir perm = %o, want 0700", perm)
	}

	// Restore into an existing directory holding only .keep.
	dstKeep := t.TempDir()
	if err := os.WriteFile(filepath.Join(dstKeep, ".keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Restore(bytes.NewReader(buf.Bytes()), dstKeep); err != nil {
		t.Fatalf("Restore into .keep dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstKeep, "vault", "identity.age")); err != nil {
		t.Fatalf("missing restored file in .keep dir: %v", err)
	}
}

func TestGateTokenAndTmpExcluded(t *testing.T) {
	src := makeSampleDataDir(t)
	if err := os.WriteFile(filepath.Join(src, "gate.token"), []byte("secret-gate-code"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "state.json.1234.tmp"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := Create(&buf, src); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if bytes.Contains(buf.Bytes(), []byte("secret-gate-code")) {
		t.Fatal("archive contains gate.token content")
	}

	dst := filepath.Join(t.TempDir(), "out")
	if err := Restore(bytes.NewReader(buf.Bytes()), dst); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "gate.token")); !os.IsNotExist(err) {
		t.Errorf("gate.token should not exist in restored dir, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "state.json.1234.tmp")); !os.IsNotExist(err) {
		t.Errorf("tmp file should not exist in restored dir, err=%v", err)
	}
}

func TestSymlinkInSourceSkipped(t *testing.T) {
	src := makeSampleDataDir(t)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(src, "link.txt")); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := Create(&buf, src); err != nil {
		t.Fatalf("Create: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "out")
	if err := Restore(bytes.NewReader(buf.Bytes()), dst); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dst, "link.txt")); !os.IsNotExist(err) {
		t.Errorf("symlink should have been skipped, err=%v", err)
	}
}

func TestTraversalRejected(t *testing.T) {
	for _, bad := range []string{"../x", "vault/../../x", "..", "a\\b"} {
		raw := buildCustomArchive(t, func(tw *tar.Writer) {
			data := []byte("evil")
			tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: bad, Size: int64(len(data)), Mode: 0o600})
			tw.Write(data)
		})
		if _, err := Check(bytes.NewReader(raw)); err == nil {
			t.Errorf("Check accepted bad path %q", bad)
		}
		if err := Restore(bytes.NewReader(raw), filepath.Join(t.TempDir(), "out")); err == nil {
			t.Errorf("Restore accepted bad path %q", bad)
		}
	}
}

func TestAbsolutePathRejected(t *testing.T) {
	raw := buildCustomArchive(t, func(tw *tar.Writer) {
		data := []byte("evil")
		tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "/etc/passwd", Size: int64(len(data)), Mode: 0o600})
		tw.Write(data)
	})
	if _, err := Check(bytes.NewReader(raw)); err == nil {
		t.Fatal("Check accepted absolute path")
	}
	if err := Restore(bytes.NewReader(raw), filepath.Join(t.TempDir(), "out")); err == nil {
		t.Fatal("Restore accepted absolute path")
	}
}

func TestSymlinkEntryRejected(t *testing.T) {
	for _, hdr := range []*tar.Header{
		{Typeflag: tar.TypeSymlink, Name: "evil", Linkname: "/etc/passwd"},
		{Typeflag: tar.TypeLink, Name: "hard", Linkname: "state.json"},
		{Typeflag: tar.TypeChar, Name: "devnull", Mode: 0o600},
	} {
		raw := buildCustomArchive(t, func(tw *tar.Writer) {
			tw.WriteHeader(hdr)
		})
		if _, err := Check(bytes.NewReader(raw)); err == nil {
			t.Errorf("Check accepted type %v", hdr.Typeflag)
		}
		if err := Restore(bytes.NewReader(raw), filepath.Join(t.TempDir(), "out")); err == nil {
			t.Errorf("Restore accepted type %v", hdr.Typeflag)
		}
	}
}

func TestNonEmptyTargetRefused(t *testing.T) {
	src := makeSampleDataDir(t)
	var buf bytes.Buffer
	if err := Create(&buf, src); err != nil {
		t.Fatal(err)
	}

	target := t.TempDir()
	existing := filepath.Join(target, "existing.txt")
	if err := os.WriteFile(existing, []byte("keep-me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Restore(bytes.NewReader(buf.Bytes()), target); err == nil {
		t.Fatal("expected Restore into non-empty target to fail")
	}
	got, err := os.ReadFile(existing)
	if err != nil || string(got) != "keep-me" {
		t.Fatalf("existing file changed: %q, err=%v", got, err)
	}
}

func TestBombLimit(t *testing.T) {
	withLimits(t, 1<<16, 1<<18)
	// Single file over 64 MiB.
	var fileBomb bytes.Buffer
	gw := gzip.NewWriter(&fileBomb)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     "huge.bin",
		Size:     MaxFileSize + 1,
		Mode:     0o600,
	}); err != nil {
		t.Fatal(err)
	}
	tw.Flush()
	gw.Close()

	if _, err := Check(bytes.NewReader(fileBomb.Bytes())); err == nil {
		t.Error("Check accepted file > 64 MiB")
	}
	if err := Restore(bytes.NewReader(fileBomb.Bytes()), filepath.Join(t.TempDir(), "out")); err == nil {
		t.Error("Restore accepted file > 64 MiB")
	}

	// Total size over 1 GiB across multiple entries.
	var totalBomb bytes.Buffer
	gw2 := gzip.NewWriter(&totalBomb)
	tw2 := tar.NewWriter(gw2)
	chunk := make([]byte, MaxFileSize)
	for i := 0; i < 17; i++ {
		name := "part-" + string(rune('a'+i))
		if err := tw2.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name,
			Size:     MaxFileSize,
			Mode:     0o600,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw2.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	tw2.Close()
	gw2.Close()

	if err := Restore(bytes.NewReader(totalBomb.Bytes()), filepath.Join(t.TempDir(), "out2")); err == nil {
		t.Error("Restore accepted archive > 1 GiB total")
	}
}

func TestFailedRestoreLeavesTargetUnchanged(t *testing.T) {
	raw := buildCustomArchive(t, func(tw *tar.Writer) {
		good := []byte("ok")
		tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "state.json", Size: int64(len(good)), Mode: 0o600})
		tw.Write(good)
		bad := []byte("bad")
		tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "../escape", Size: int64(len(bad)), Mode: 0o600})
		tw.Write(bad)
	})

	// Case 1: target exists with only .keep.
	dir := t.TempDir()
	keepPath := filepath.Join(dir, ".keep")
	if err := os.WriteFile(keepPath, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Restore(bytes.NewReader(raw), dir); err == nil {
		t.Fatal("expected Restore to fail on bad second entry")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != ".keep" {
		t.Fatalf("target dir modified after failed restore: %v", ents)
	}

	// Case 2: target does not exist yet.
	nonExistent := filepath.Join(t.TempDir(), "newdir")
	if err := Restore(bytes.NewReader(raw), nonExistent); err == nil {
		t.Fatal("expected Restore to fail")
	}
	if _, err := os.Lstat(nonExistent); !os.IsNotExist(err) {
		t.Fatalf("non-existent target was created on failed restore: err=%v", err)
	}
}


func withLimits(t *testing.T, file, total int64) {
	f, tt := MaxFileSize, MaxTotalSize
	MaxFileSize, MaxTotalSize = file, total
	t.Cleanup(func() { MaxFileSize, MaxTotalSize = f, tt })
}

func tarOf(t *testing.T, files map[string]string) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for n, v := range files {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: n, Size: int64(len(v)), Mode: 0o600}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(v))
	}
	tw.Close()
	gz.Close()
	return &b
}

var goodFiles = map[string]string{"vault/identity.age": "i", "vault/recipient.txt": "r", "state.json": "{}"}

func TestRestoreIntoFreshServerDirectory(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{".keep", "gate.token"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := Restore(tarOf(t, goodFiles), dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "vault", "identity.age")); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".ucr-restore") {
			t.Fatal("temporary directory left behind")
		}
	}
}

func TestRestoreWorksWhenParentIsReadOnly(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory modes")
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(parent, 0o700) })
	if err := Restore(tarOf(t, goodFiles), dir); err != nil {
		t.Fatalf("read-only parent: %v", err)
	}
}

func TestRestoreRequiresTheVault(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Restore(tarOf(t, map[string]string{"state.json": "{}"}), dir); err == nil {
		t.Fatal("partial archive restored")
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed restore created the target")
	}
}
