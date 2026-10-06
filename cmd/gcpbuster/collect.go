package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// Legacy argument construction retained for compatibility tests only.
// No external process is launched under the exact viewer-role constraint.
func scoutArgs(scope, raw, keyFile string) ([]string, error) {
	if !scopePattern.MatchString(scope) {
		return nil, fmt.Errorf("specify --scope as projects/ID, folders/NUMBER or organizations/NUMBER")
	}
	parts := strings.SplitN(scope, "/", 2)
	flag := map[string]string{"projects": "--project-id", "folders": "--folder-id", "organizations": "--organization-id"}[parts[0]]
	args := []string{"gcp", flag, parts[1], "--no-browser", "--report-dir", raw}
	if keyFile != "" {
		args = append(args, "--service-account", keyFile)
	} else {
		args = append(args, "--user-account")
	}
	return args, nil
}

func collectCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "collect", Short: "Disabled external collector (viewer-role boundary)", RunE: func(*cobra.Command, []string) error {
		return fmt.Errorf("external ScoutSuite execution is disabled: GCPBuster cannot enforce the three allowed Viewer roles on an external process; use native viewer-scoped scan or offline inventory")
	}}
	cmd.Flags().String("scope", "", "Legacy option; external collection is disabled")
	cmd.Flags().String("engagement", "", "Legacy option; external collection is disabled")
	cmd.Flags().String("service-account-file", "", "Legacy option; external collection is disabled")
	return cmd
}
