package web

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCatalogExtraDir(t *testing.T) {
	e := setup(t, time.Minute)

	// Missing directory returns only embedded entries.
	e.s.CatalogDir = filepath.Join(t.TempDir(), "does-not-exist")
	code, raw := e.raw("GET", "/catalog.json", nil, nil)
	if code != 200 {
		t.Fatalf("missing dir status: %d", code)
	}
	var embedded []catalogEntry
	if err := json.Unmarshal(raw, &embedded); err != nil {
		t.Fatalf("unmarshal embedded: %v", err)
	}
	if len(embedded) == 0 {
		t.Fatal("expected embedded entries")
	}

	dir := t.TempDir()
	e.s.CatalogDir = dir

	// 1. Good extra entry and duplicate of an embedded entry and invalid profile in 01-mixed.json.
	mixed := `[
		{
			"group": "Extra",
			"title": "Good One",
			"secrets": ["my_tok"],
			"hint": "Hint 1",
			"profile": {
				"name": "extra-good-one",
				"description": "First good extra profile",
				"risk": "low",
				"http": {
					"method": "GET",
					"url": "https://api.example.com/v1/one",
					"headers": {"Authorization": "Bearer {{secret:my_tok}}"}
				}
			}
		},
		{
			"group": "Extra",
			"title": "Duplicate Embedded",
			"secrets": ["github_token"],
			"hint": "Dup",
			"profile": {
				"name": "github-list-repos",
				"description": "Should be skipped",
				"risk": "low",
				"http": {
					"method": "GET",
					"url": "https://api.example.com/dup"
				}
			}
		},
		{
			"group": "Extra",
			"title": "Invalid Profile",
			"secrets": [],
			"hint": "Bad URL",
			"profile": {
				"name": "invalid-profile",
				"description": "Bad",
				"risk": "low",
				"http": {
					"method": "GET",
					"url": "ftp://bad.example.com"
				}
			}
		}
	]`
	if err := os.WriteFile(filepath.Join(dir, "01-mixed.json"), []byte(mixed), 0o600); err != nil {
		t.Fatal(err)
	}

	// 2. Broken JSON file in 02-broken.json.
	if err := os.WriteFile(filepath.Join(dir, "02-broken.json"), []byte(`[{not valid json`), 0o600); err != nil {
		t.Fatal(err)
	}

	// 3. Second good file with a duplicate of extra-good-one and a new extra-good-two in 03-second.json.
	second := `[
		{
			"group": "Extra",
			"title": "Dup Extra",
			"secrets": [],
			"hint": "Dup of extra-good-one",
			"profile": {
				"name": "extra-good-one",
				"description": "Duplicate of earlier extra",
				"risk": "low",
				"http": {
					"method": "GET",
					"url": "https://api.example.com/v1/dup"
				}
			}
		},
		{
			"group": "Extra",
			"title": "Good Two",
			"secrets": ["my_tok"],
			"hint": "Hint 2",
			"profile": {
				"name": "extra-good-two",
				"description": "Second good extra profile",
				"risk": "low",
				"http": {
					"method": "GET",
					"url": "https://api.example.com/v1/two",
					"headers": {"Authorization": "Bearer {{secret:my_tok}}"}
				}
			}
		}
	]`
	if err := os.WriteFile(filepath.Join(dir, "03-second.json"), []byte(second), 0o600); err != nil {
		t.Fatal(err)
	}

	// 4. Ignored items: subdirectory, oversized file (>1 MiB), symlink.
	if err := os.Mkdir(filepath.Join(dir, "04-subdir.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte(" "), (1<<20)+10)
	if err := os.WriteFile(filepath.Join(dir, "05-huge.json"), big, 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte(`[{"group":"X","title":"Sym","secrets":[],"profile":{"name":"from-symlink","risk":"low","http":{"method":"GET","url":"https://api.example.com/sym"}}}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink(outside, filepath.Join(dir, "06-symlink.json"))

	code, raw = e.raw("GET", "/catalog.json", nil, nil)
	if code != 200 {
		t.Fatalf("catalog status: %d", code)
	}
	var got []catalogEntry
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal got: %v", err)
	}
	if len(got) != len(embedded)+2 {
		t.Fatalf("got %d entries, want %d", len(got), len(embedded)+2)
	}
	if got[len(embedded)].Profile.Name != "extra-good-one" || got[len(embedded)].Title != "Good One" {
		t.Fatalf("unexpected first extra entry: %+v", got[len(embedded)])
	}
	if got[len(embedded)+1].Profile.Name != "extra-good-two" || got[len(embedded)+1].Title != "Good Two" {
		t.Fatalf("unexpected second extra entry: %+v", got[len(embedded)+1])
	}
	for _, item := range got {
		if item.Profile.Name == "github-list-repos" && item.Title == "Duplicate Embedded" {
			t.Fatal("duplicate embedded profile was not skipped")
		}
		if item.Profile.Name == "invalid-profile" {
			t.Fatal("invalid profile was not skipped")
		}
		if item.Profile.Name == "from-symlink" {
			t.Fatal("symlink file was not ignored")
		}
	}
}
