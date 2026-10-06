package sourceaudit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func syntheticReview(body string) ReviewLedger {
	return ReviewLedger{SchemaVersion: 1, ReviewedAt: "2026-10-05", Profile: []string{"roles/viewer", "roles/resourcemanager.folderViewer", "roles/resourcemanager.organizationViewer"}, Sources: []SourceReview{{ID: "example", Root: "hacktricks", Path: "page.md", SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(body))), ReviewScope: "entire_file", Behaviors: []BehaviorReview{{ID: "configuration", Location: ReviewLocation{Heading: "Example", StartLine: 1, EndLine: 2}, Description: "Specific configuration observation, not complete runtime detection", Status: "implemented_detection", Evaluators: []string{"public_sql"}, Tests: []ReviewTest{{Path: "internal/checks/checks_test.go", Test: "TestExample"}}}}}}}
}

func TestReviewFreshnessNeverPromotesSourceCoverage(t *testing.T) {
	root := t.TempDir()
	body := "# Example\nconfiguration\n"
	if err := os.WriteFile(filepath.Join(root, "page.md"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	ledger := syntheticReview(body)
	data, _ := json.Marshal(ledger)
	summary := map[string]int{}
	got, err := inspectReviews(data, root, root, summary)
	if err != nil || got.Sources[0].SourceValidation != "current" || summary["review_assertions_implemented_detection"] != 1 || summary["behaviorally_verified_sections"] != 0 {
		t.Fatal(got, summary, err)
	}
	if err := os.WriteFile(filepath.Join(root, "page.md"), []byte(body+"changed"), 0600); err != nil {
		t.Fatal(err)
	}
	summary = map[string]int{}
	got, err = inspectReviews(data, root, root, summary)
	if err != nil || got.Sources[0].SourceValidation != "stale" || summary["review_assertions_implemented_detection"] != 0 {
		t.Fatal(got, summary, err)
	}
	got, err = inspectReviews(data, t.TempDir(), root, map[string]int{})
	if err != nil || got.Sources[0].SourceValidation != "unavailable" {
		t.Fatal(got, err)
	}
}

func TestReviewSchemaRejectsUnsupportedAssertions(t *testing.T) {
	for _, mutate := range []func(*ReviewLedger){
		func(l *ReviewLedger) { l.Profile = append(l.Profile, "roles/owner") },
		func(l *ReviewLedger) { l.Sources[0].Path = "../outside" },
		func(l *ReviewLedger) { l.Sources[0].Behaviors[0].Status = "complete" },
		func(l *ReviewLedger) { l.Sources[0].Behaviors[0].Tests = nil },
		func(l *ReviewLedger) { l.Sources[0].Behaviors[0].Evaluators = []string{"made_up"} },
		func(l *ReviewLedger) { l.Sources[0].Behaviors[0].Tests[0].Path = "/outside_test.go" },
		func(l *ReviewLedger) { l.Sources[0].Behaviors[0].Status = "unsupported_permission" },
		func(l *ReviewLedger) { l.Sources[0].SourceValidation = "current" },
		func(l *ReviewLedger) {
			l.Sources[0].Behaviors[0].Methods = []ReviewMethod{{Method: "EXEC", Endpoint: "https://example.invalid"}}
		},
		func(l *ReviewLedger) {
			l.Sources[0].Behaviors[0].Methods = []ReviewMethod{{Method: "GET", Endpoint: "http://example.invalid"}}
		},
		func(l *ReviewLedger) {
			l.Sources[0].Behaviors[0].Methods = []ReviewMethod{{Method: "GET", Endpoint: "https://example.invalid", Permissions: []string{"*"}}}
		},
		func(l *ReviewLedger) { l.Sources = append(l.Sources, l.Sources[0]) },
	} {
		ledger := syntheticReview("# Example\nconfiguration\n")
		mutate(&ledger)
		data, _ := json.Marshal(ledger)
		if _, err := decodeReviews(data); err == nil {
			t.Fatal("accepted invalid review", string(data))
		}
	}
}

func TestEmbeddedReviewReferencesExist(t *testing.T) {
	ledger, err := decodeReviews(reviewData)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range ledger.Sources {
		for _, behavior := range source.Behaviors {
			for _, ref := range behavior.Tests {
				path := filepath.Join("..", "..", filepath.FromSlash(ref.Path))
				parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
				if err != nil {
					t.Fatal(source.ID, behavior.ID, err)
				}
				found := false
				for _, decl := range parsed.Decls {
					if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == ref.Test && strings.HasPrefix(fn.Name.Name, "Test") {
						found = true
					}
				}
				if !found {
					t.Errorf("%s/%s references missing test %s:%s", source.ID, behavior.ID, ref.Path, ref.Test)
				}
			}
		}
	}
}
