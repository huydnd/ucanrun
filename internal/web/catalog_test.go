package web

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogEmbeddedIsValid(t *testing.T) {
	cat := readCatalog("")
	if len(cat) < 6 {
		t.Fatalf("only %d entries", len(cat))
	}
	for _, e := range cat {
		if err := validEntry(e); err != nil {
			t.Errorf("%+v: %v", e.Service, err)
		}
	}
}

func TestCatalogExtraDir(t *testing.T) {
	base := len(readCatalog(""))
	dir := t.TempDir()
	good := `[{"service":{"name":"acme","base_url":"https://api.acme.example","auth":{"type":"bearer","secret":"acme_token"}},
	  "hint":"x","actions":[{"title":"Ping","profile":{"name":"acme-ping","risk":"low","http":{"method":"GET","url":"/ping"}}}]}]`
	writeFile(t, dir, "a-good.json", good)
	writeFile(t, dir, "b-broken.json", `[{`)
	writeFile(t, dir, "c-badhost.json", `[{"service":{"name":"evil","base_url":"https://{{x}}.example","auth":{"type":"none"}},"actions":[{"title":"x","profile":{"name":"evil-x","risk":"low","http":{"method":"GET","url":"/"}}}]}]`)
	writeFile(t, dir, "d-escape.json", `[{"service":{"name":"esc","base_url":"https://a.example","auth":{"type":"none"}},"actions":[{"title":"x","profile":{"name":"esc-x","risk":"low","http":{"method":"GET","url":"//evil.example/"}}}]}]`)
	writeFile(t, dir, "e-dup.json", `[{"service":{"name":"github","base_url":"https://a.example","auth":{"type":"none"}},"actions":[{"title":"x","profile":{"name":"dup-x","risk":"low","http":{"method":"GET","url":"/"}}}]}]`)
	writeFile(t, dir, "f-dupaction.json", `[{"service":{"name":"other","base_url":"https://a.example","auth":{"type":"none"}},"actions":[{"title":"x","profile":{"name":"github-whoami","risk":"low","http":{"method":"GET","url":"/"}}}]}]`)
	os.Symlink(filepath.Join(dir, "a-good.json"), filepath.Join(dir, "g-link.json"))
	got := readCatalog(dir)
	if len(got) != base+1 || got[base].Service == nil || got[base].Service.Name != "acme" {
		t.Fatalf("got %d entries, want %d plus acme", len(got), base)
	}
	if len(readCatalog(filepath.Join(dir, "missing"))) != base {
		t.Fatal("missing dir changed the catalog")
	}
}
