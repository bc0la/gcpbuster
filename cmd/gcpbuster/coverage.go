package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/bc0la/gcpbuster/internal/sourceaudit"
	"github.com/spf13/cobra"
)

func coverageCommand() *cobra.Command {
	var root, awsRoot, output string
	var summary bool
	c := &cobra.Command{Use: "coverage", Short: "Audit source pages and AWS equivalence candidates without asserting implementation completeness", RunE: func(cmd *cobra.Command, _ []string) error {
		if root == "" || awsRoot == "" {
			return fmt.Errorf("--hacktricks-root and --bezosbuster-root are required")
		}
		a, err := sourceaudit.Inspect(root, awsRoot)
		if err != nil {
			return err
		}
		var value any = a
		if summary {
			value = a.Summary
		}
		w := cmd.OutOrStdout()
		if output != "" {
			f, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			defer f.Close()
			w = f
		}
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		return e.Encode(value)
	}}
	c.Flags().StringVar(&root, "hacktricks-root", "", "Local hacktricks-cloud source checkout")
	c.Flags().StringVar(&awsRoot, "bezosbuster-root", "", "Local BezosBuster source checkout")
	c.Flags().StringVar(&output, "output", "", "Create a new JSON audit file; existing files are not overwritten")
	c.Flags().BoolVar(&summary, "summary", false, "Output only source and mapping counts")
	return c
}
