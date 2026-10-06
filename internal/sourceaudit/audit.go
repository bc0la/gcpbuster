// Package sourceaudit inventories the source corpus without confusing a source
// reference or permission mention with an implemented behavioral check.
package sourceaudit

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bc0la/gcpbuster/internal/checks"
	"github.com/bc0la/gcpbuster/internal/permissioncatalog"
)

type Section struct {
	Line    int    `json:"line"`
	Heading string `json:"heading"`
	Status  string `json:"status"`
}
type Page struct {
	Path                    string    `json:"path"`
	SHA256                  string    `json:"sha256"`
	Stage                   string    `json:"source_stage"`
	Sections                []Section `json:"sections"`
	ReferencedBy            []string  `json:"referenced_by_modules"`
	ClassifiedPermissions   []string  `json:"classified_permission_mentions"`
	UnclassifiedIdentifiers []string  `json:"unclassified_permission_like_identifiers"`
	Status                  string    `json:"status"`
}
type Equivalent struct {
	Module     string   `json:"bezosbuster_module"`
	Candidates []string `json:"candidate_equivalents"`
	Status     string   `json:"status"`
}
type Audit struct {
	Pages                   []Page         `json:"pages"`
	Equivalents             []Equivalent   `json:"bezosbuster_equivalents"`
	Summary                 map[string]int `json:"summary"`
	Limitations             []string       `json:"limitations"`
	PermissionCatalogSHA256 string         `json:"permission_catalog_sha256"`
	Reviews                 ReviewLedger   `json:"behavior_reviews"`
}

var heading = regexp.MustCompile(`^#{1,6}\s+(.+?)\s*#*$`)
var identifier = regexp.MustCompile("`([a-z][a-zA-Z0-9]*(?:\\.[a-zA-Z][a-zA-Z0-9]*){2,})`")

func Inspect(hacktricksRoot, bezosRoot string) (Audit, error) {
	a := Audit{Summary: map[string]int{}, PermissionCatalogSHA256: permissioncatalog.SHA256(), Limitations: []string{
		"This is a completeness backlog, not proof of full coverage. Every section still requires an explicit behavior-to-check mapping and verification.",
		"A module citing a page proves only that the page is referenced; permission mentions prove only catalog overlap, not detection of its techniques or prerequisites.",
		"Unclassified identifiers include non-permission API names and examples; they require source review. Headings inside fenced code blocks are excluded.",
		"AWS candidate mappings retain review_required until behavior, inputs, collection and tests establish applicable equivalence.",
	}}
	for _, root := range []string{"gcp-security", "workspace-security"} {
		base := filepath.Join(hacktricksRoot, "src", "pentesting-cloud", root)
		if _, err := os.Stat(base); err != nil {
			return a, err
		}
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".md") {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(hacktricksRoot, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			page := Page{Path: rel, SHA256: fmt.Sprintf("%x", sha256.Sum256(body)), Status: "unmapped", ReferencedBy: []string{}, ClassifiedPermissions: []string{}, UnclassifiedIdentifiers: []string{}, Sections: []Section{}}
			page.Stage = strings.Split(strings.TrimPrefix(filepath.ToSlash(path), filepath.ToSlash(base)+"/"), "/")[0]
			url := "https://cloud.hacktricks.wiki/en/" + strings.TrimSuffix(strings.TrimPrefix(rel, "src/"), ".md") + ".html"
			for _, c := range checks.All {
				if c.Source == url {
					page.ReferencedBy = append(page.ReferencedBy, c.ID)
				}
			}
			if len(page.ReferencedBy) > 0 {
				page.Status = "reference_only"
				a.Summary["referenced_pages"]++
			}
			scan := bufio.NewScanner(strings.NewReader(string(body)))
			scan.Buffer(make([]byte, 4096), 4<<20)
			line := 0
			fence := ""
			fenceLen := 0
			for scan.Scan() {
				line++
				text := scan.Text()
				trim := strings.TrimSpace(text)
				if strings.HasPrefix(trim, "```") || strings.HasPrefix(trim, "~~~") {
					marker := trim[:1]
					n := 0
					for n < len(trim) && trim[n:n+1] == marker {
						n++
					}
					if fence == "" {
						fence = marker
						fenceLen = n
					} else if marker == fence && n >= fenceLen && strings.TrimSpace(trim[n:]) == "" {
						fence = ""
					}
					continue
				}
				if fence != "" {
					continue
				}
				if m := heading.FindStringSubmatch(text); m != nil {
					page.Sections = append(page.Sections, Section{line, m[1], "unverified"})
				}
			}
			if err := scan.Err(); err != nil {
				return err
			}
			known, unknown := map[string]bool{}, map[string]bool{}
			for _, m := range identifier.FindAllStringSubmatch(string(body), -1) {
				if _, ok := permissioncatalog.Severity(m[1]); ok {
					known[m[1]] = true
				} else {
					unknown[m[1]] = true
				}
			}
			for p := range known {
				page.ClassifiedPermissions = append(page.ClassifiedPermissions, p)
			}
			sort.Strings(page.ClassifiedPermissions)
			for p := range unknown {
				page.UnclassifiedIdentifiers = append(page.UnclassifiedIdentifiers, p)
			}
			sort.Strings(page.UnclassifiedIdentifiers)
			a.Summary[root+"_pages"]++
			a.Summary["sections_requiring_verification"] += len(page.Sections)
			a.Pages = append(a.Pages, page)
			return nil
		})
		if err != nil {
			return a, err
		}
	}
	sort.Slice(a.Pages, func(i, j int) bool { return a.Pages[i].Path < a.Pages[j].Path })
	entries, err := os.ReadDir(filepath.Join(bezosRoot, "internal", "module"))
	if err != nil {
		return a, err
	}
	for _, d := range entries {
		if !d.IsDir() || d.Name() == "exttool" {
			continue
		}
		candidate := awsCandidates[d.Name()]
		if candidate == nil {
			candidate = []string{}
		}
		a.Equivalents = append(a.Equivalents, Equivalent{d.Name(), candidate, "review_required"})
	}
	a.Summary["pages"] = len(a.Pages)
	a.Summary["bezosbuster_modules"] = len(a.Equivalents)
	a.Summary["behaviorally_verified_sections"] = 0
	a.Summary["classified_permissions"] = permissioncatalog.Count()
	a.Reviews, err = inspectReviews(reviewData, hacktricksRoot, bezosRoot, a.Summary)
	if err != nil {
		return a, err
	}
	a.Limitations = append(a.Limitations, "Behavior-review assertions are bound to source hashes. Current hashes prove freshness only; referenced tests are not executed by this command. Stale/unavailable reviews do not contribute assertion counts. No review assertion automatically verifies a whole heading, page or AWS module.")
	return a, nil
}

var awsCandidates = map[string][]string{
	"scoutsuite": {"scoutsuite"}, "steampipe_perimeter": {"firewall_ingress", "public_iam", "public_sql", "public_gke", "public_serverless"},
	"ec2_imdsv1": {"compute_metadata", "gke_security"}, "bedrock": {"vertex_ai_posture"},
	"secrets_scan": {"configuration_secrets", "service_account_keys", "api_key_restrictions", "gcs_content_secrets", "log_content_secrets"}, "lambda_env": {"configuration_secrets", "gcs_content_secrets"}, "codebuild_env": {"configuration_secrets", "gcs_content_secrets", "log_content_secrets"}, "ec2_userdata": {"configuration_secrets"}, "ecs_ecr_taskdefs": {"configuration_secrets"}, "ssm_commands": {"configuration_secrets", "log_content_secrets"},
	"iam_integrations": {"iam_privileges", "federation_trust", "iam_permission_risks", "iam_permission_combinations"}, "bluecloudpeass": {"iam_permission_risks", "iam_permission_combinations"}, "cognito": {"identity_platform"},
	"s3_anon": {"public_iam", "storage_acl", "gcs_anonymous_access"}, "public_rds": {"public_sql"}, "public_redshift": {"public_bigquery"}, "public_documentdb": {"public_sql", "public_iam"}, "public_neptune": {"public_sql", "public_iam"}, "public_opensearch": {"public_iam"},
	"public_mq": {"public_iam"}, "public_msk": {"public_iam"}, "public_sns": {"public_iam"}, "public_sqs": {"public_iam"}, "public_ecr": {"public_iam"}, "ecr_repo_policy": {"public_iam"}, "public_amis": {"public_iam"}, "public_snapshots": {"public_iam"}, "kms_key_exposure": {"public_iam", "iam_permission_risks"}, "apigw_lambda": {"public_iam", "public_serverless"}, "subdomain_takeover": {"dns_dangling"},
}
