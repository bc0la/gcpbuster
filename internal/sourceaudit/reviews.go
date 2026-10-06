package sourceaudit

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bc0la/gcpbuster/internal/checks"
)

//go:embed reviews.json
var reviewData []byte

// Reviews are explicit human/agent assertions tied to exact source revisions.
// Matching hashes establish freshness only, not that tests ran or a behavior
// is completely detected. They never promote whole pages/sections to covered.
type ReviewLedger struct {
	SchemaVersion int            `json:"schema_version"`
	ReviewedAt    string         `json:"reviewed_at"`
	Profile       []string       `json:"profile"`
	Sources       []SourceReview `json:"sources"`
}

type SourceReview struct {
	ID               string           `json:"id"`
	Root             string           `json:"root"`
	Path             string           `json:"path"`
	SHA256           string           `json:"sha256"`
	ReviewScope      string           `json:"review_scope"`
	Behaviors        []BehaviorReview `json:"behaviors"`
	SourceValidation string           `json:"source_validation,omitempty"`
}

type BehaviorReview struct {
	ID          string         `json:"id"`
	Location    ReviewLocation `json:"location"`
	Description string         `json:"description"`
	Status      string         `json:"status"`
	Methods     []ReviewMethod `json:"methods"`
	Evaluators  []string       `json:"evaluators"`
	Tests       []ReviewTest   `json:"tests"`
	Limitations []string       `json:"limitations"`
}
type ReviewLocation struct {
	Heading   string `json:"heading"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}
type ReviewMethod struct {
	Method      string   `json:"method"`
	Endpoint    string   `json:"endpoint"`
	Permissions []string `json:"permissions"`
}
type ReviewTest struct {
	Path string `json:"path"`
	Test string `json:"test"`
}

func safeReviewPath(path string) bool {
	return path != "" && !filepath.IsAbs(path) && filepath.ToSlash(filepath.Clean(path)) == path && path != "." && path != ".." && !strings.HasPrefix(path, "../") && !strings.Contains(path, "\\")
}

func decodeReviews(data []byte) (ReviewLedger, error) {
	var ledger ReviewLedger
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ledger); err != nil {
		return ledger, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return ledger, fmt.Errorf("review ledger has trailing data")
	}
	if ledger.SchemaVersion != 1 {
		return ledger, fmt.Errorf("unsupported review schema")
	}
	if _, err := time.Parse("2006-01-02", ledger.ReviewedAt); err != nil {
		return ledger, fmt.Errorf("invalid review date")
	}
	roles := map[string]bool{"roles/viewer": false, "roles/resourcemanager.folderViewer": false, "roles/resourcemanager.organizationViewer": false}
	for _, role := range ledger.Profile {
		seen, ok := roles[role]
		if !ok || seen {
			return ledger, fmt.Errorf("invalid review permission profile")
		}
		roles[role] = true
	}
	if len(ledger.Profile) != len(roles) {
		return ledger, fmt.Errorf("incomplete review permission profile")
	}
	evaluators := map[string]bool{}
	for _, check := range checks.All {
		evaluators[check.ID] = true
	}
	ids := map[string]bool{}
	paths := map[string]bool{}
	for _, source := range ledger.Sources {
		pathKey := source.Root + ":" + source.Path
		if source.ID == "" || ids[source.ID] || paths[pathKey] || (source.Root != "hacktricks" && source.Root != "bezosbuster") || !safeReviewPath(source.Path) || source.ReviewScope != "entire_file" || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(source.SHA256) || source.SourceValidation != "" || len(source.Behaviors) == 0 {
			return ledger, fmt.Errorf("invalid or duplicate source review %q", source.ID)
		}
		ids[source.ID], paths[pathKey] = true, true
		behaviors := map[string]bool{}
		for _, b := range source.Behaviors {
			if b.ID == "" || behaviors[b.ID] || b.Description == "" || b.Location.Heading == "" || b.Location.StartLine < 1 || b.Location.EndLine < b.Location.StartLine {
				return ledger, fmt.Errorf("invalid behavior in %s", source.ID)
			}
			behaviors[b.ID] = true
			switch b.Status {
			case "implemented_detection":
				if len(b.Evaluators) == 0 || len(b.Tests) == 0 {
					return ledger, fmt.Errorf("implemented assertion lacks evidence in %s", source.ID)
				}
			case "partial", "unsupported_permission":
				if len(b.Limitations) == 0 {
					return ledger, fmt.Errorf("gap lacks limitation in %s", source.ID)
				}
			case "non_detection_context":
			default:
				return ledger, fmt.Errorf("invalid behavior status in %s", source.ID)
			}
			for _, evaluator := range b.Evaluators {
				if !evaluators[evaluator] {
					return ledger, fmt.Errorf("unknown review evaluator %s", evaluator)
				}
			}
			for _, test := range b.Tests {
				if !safeReviewPath(test.Path) || !strings.HasSuffix(test.Path, "_test.go") || !regexp.MustCompile(`^Test[A-Za-z0-9_]+$`).MatchString(test.Test) {
					return ledger, fmt.Errorf("invalid review test reference in %s", source.ID)
				}
			}
			for _, method := range b.Methods {
				u, parseErr := url.Parse(method.Endpoint)
				if !regexp.MustCompile(`^(GET|POST|PUT|PATCH|DELETE|HEAD)$`).MatchString(method.Method) || parseErr != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(u.Host, "{}") {
					return ledger, fmt.Errorf("invalid review method in %s", source.ID)
				}
				for _, permission := range method.Permissions {
					if !regexp.MustCompile(`^([A-Za-z][A-Za-z0-9]*(\.[A-Za-z][A-Za-z0-9]*){2,}|[a-z][a-z0-9]*\.googleapis\.com/[A-Za-z][A-Za-z0-9]*\.[A-Za-z][A-Za-z0-9]*)$`).MatchString(permission) {
						return ledger, fmt.Errorf("invalid review permission in %s", source.ID)
					}
				}
			}
		}
	}
	return ledger, nil
}

func inspectReviews(data []byte, hacktricksRoot, bezosRoot string, summary map[string]int) (ReviewLedger, error) {
	ledger, err := decodeReviews(data)
	if err != nil {
		return ledger, err
	}
	for i := range ledger.Sources {
		source := &ledger.Sources[i]
		root := hacktricksRoot
		if source.Root == "bezosbuster" {
			root = bezosRoot
		}
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(source.Path)))
		switch {
		case err != nil:
			source.SourceValidation = "unavailable"
		case fmt.Sprintf("%x", sha256.Sum256(body)) != source.SHA256:
			source.SourceValidation = "stale"
		default:
			source.SourceValidation = "current"
			lines := bytes.Count(body, []byte{'\n'}) + 1
			if len(body) == 0 || body[len(body)-1] == '\n' {
				lines--
			}
			for _, behavior := range source.Behaviors {
				if behavior.Location.EndLine > lines {
					source.SourceValidation = "invalid_location"
					break
				}
			}
		}
		summary["review_sources_"+source.SourceValidation]++
		if source.SourceValidation == "current" {
			for _, behavior := range source.Behaviors {
				summary["review_assertions_"+behavior.Status]++
			}
		}
	}
	return ledger, nil
}
