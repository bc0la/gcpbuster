package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFormatsAndIncompletePages(t *testing.T) {
	a := `{"name":"test","assetType":"storage.googleapis.com/Bucket","resource":{"data":{}}}`
	for _, tc := range []struct {
		name, input string
		count       int
		bad         bool
		incomplete  bool
	}{
		{"JSONL", a + "\n" + a, 2, false, false},
		{"array", "[" + a + "]", 1, false, false},
		{"snapshot", `{"assets":[` + a + `]}`, 1, false, false},
		{"incomplete page", `{"assets":[` + a + `],"nextPageToken":"remaining"}`, 1, false, true},
		{"malformed", `{"assets":[`, 0, true, false},
		{"unknown object", `{"unexpected":true}`, 0, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.json")
			if err := os.WriteFile(path, []byte(tc.input), 0600); err != nil {
				t.Fatal(err)
			}
			s, err := Load(path)
			if (err != nil) != tc.bad {
				t.Fatalf("unexpected error %v", err)
			}
			if !tc.bad && len(s.Assets) != tc.count {
				t.Fatal(s)
			}
			if tc.incomplete && (len(s.Coverage) != 1 || s.Coverage[0].Status != "failed") {
				t.Fatal("incomplete page not surfaced", s)
			}
		})
	}
}
