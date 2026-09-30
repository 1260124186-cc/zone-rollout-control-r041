package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"solo-0014-zone-rollout-control/internal/recovery"
)

const maxListedObjects = 20

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("zrcrestore", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintf(stderr, "usage: zrcrestore --snapshot <candidate.json> --state <target.json> [--confirm] [--force] [--report text|json]\n\n")
		fmt.Fprintf(stderr, "Offline snapshot recovery. Without --confirm only prints the verification report;\n")
		fmt.Fprintf(stderr, "nothing is written and no service is contacted.\n\n")
		flags.PrintDefaults()
	}
	var (
		snapshotPath string
		targetPath   string
		confirm      bool
		force        bool
		reportFormat string
	)
	flags.StringVar(&snapshotPath, "snapshot", "", "candidate snapshot file to verify and restore (required)")
	flags.StringVar(&targetPath, "state", "data/zrc-state.json", "target state snapshot path")
	flags.BoolVar(&confirm, "confirm", false, "explicit confirmation to atomically write the target snapshot")
	flags.BoolVar(&force, "force", false, "replace target when it contains a different (conflicting) snapshot")
	flags.StringVar(&reportFormat, "report", "text", "report format: text or json")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if snapshotPath == "" {
		flags.Usage()
		return fmt.Errorf("--snapshot is required")
	}
	if reportFormat != "text" && reportFormat != "json" {
		return fmt.Errorf("--report must be text or json")
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}

	options := recovery.Options{
		CandidatePath: snapshotPath,
		TargetPath:    targetPath,
		Confirm:       confirm,
		Force:         force,
	}
	report, err := recovery.Apply(options)
	if err != nil {
		if report != nil {
			if reportFormat == "json" {
				emitJSON(stdout, report)
			} else {
				renderText(stdout, report)
			}
		}
		switch {
		case report != nil && report.Outcome == recovery.OutcomeLocked:
			os.Exit(3)
		case report != nil && report.Outcome == recovery.OutcomeWriteFailed:
			os.Exit(5)
		default:
			return err
		}
	}

	if reportFormat == "json" {
		emitJSON(stdout, report)
	} else {
		renderText(stdout, report)
	}

	switch report.Outcome {
	case recovery.OutcomeInvalid:
		os.Exit(2)
	case recovery.OutcomeBlocked:
		os.Exit(4)
	case recovery.OutcomeWriteFailed:
		os.Exit(5)
	}
	return nil
}

func emitJSON(writer io.Writer, report *recovery.Report) {
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintln(writer, err)
		return
	}
	fmt.Fprintln(writer, string(encoded))
}

func renderText(writer io.Writer, report *recovery.Report) {
	fmt.Fprintln(writer, "Offline snapshot recovery report")
	fmt.Fprintln(writer, "=================================")
	fmt.Fprintf(writer, "candidate: %s (%d bytes)\n", report.CandidatePath, report.CandidateBytes)
	fmt.Fprintf(writer, "candidate sha256: %s\n", report.CandidateDigest)
	fmt.Fprintf(writer, "target:    %s\n", report.TargetPath)
	if report.TargetPresent {
		fmt.Fprintf(writer, "target sha256:    %s (readable: %t)\n", report.TargetDigest, report.TargetReadable)
	} else {
		fmt.Fprintln(writer, "target:    not present (initial restore)")
	}
	fmt.Fprintf(writer, "schema_version: %d  state_revision: %d\n", report.SchemaVersion, report.StateRevision)
	fmt.Fprintf(writer, "identity: %s  confirmed: %t  force: %t\n", report.Diff.Identity, report.Confirmed, report.Force)

	c := report.Counts
	fmt.Fprintln(writer)
	fmt.Fprintln(writer, "Post-restore counts (identical to service startup reads):")
	fmt.Fprintf(writer, "  plans=%d revisions=%d nodes=%d leases=%d lease_groups=%d probes=%d assessments=%d audit_events=%d\n",
		c.Plans, c.Revisions, c.Nodes, c.Leases, c.LeaseGroups, c.Probes, c.Assessments, c.AuditEvents)
	fmt.Fprintf(writer, "  lease_request_index=%d assessment_request_index=%d\n",
		c.LeaseIndexKeys, c.AssessmentIndex)

	if report.TargetPresent && report.TargetReadable {
		t := report.Diff.Target
		fmt.Fprintln(writer)
		fmt.Fprintln(writer, "Current target counts:")
		fmt.Fprintf(writer, "  plans=%d revisions=%d nodes=%d leases=%d lease_groups=%d probes=%d assessments=%d audit_events=%d\n",
			t.Plans, t.Revisions, t.Nodes, t.Leases, t.LeaseGroups, t.Probes, t.Assessments, t.AuditEvents)
		fmt.Fprintf(writer, "  lease_request_index=%d assessment_request_index=%d\n",
			t.LeaseIndexKeys, t.AssessmentIndex)
	}

	fmt.Fprintln(writer)
	fmt.Fprintf(writer, "Objects: %d to replace, %d to add, %d to remove; index entries changing: %d\n",
		len(report.Diff.Objects.Replace), len(report.Diff.Objects.Add), len(report.Diff.Objects.Remove), len(report.Diff.Indexes))
	listObjects(writer, "REPLACE", report.Diff.Objects.Replace)
	listObjects(writer, "ADD", report.Diff.Objects.Add)
	listObjects(writer, "REMOVE", report.Diff.Objects.Remove)
	if len(report.Diff.Indexes) > 0 {
		fmt.Fprintln(writer, "Index changes:")
		limit := len(report.Diff.Indexes)
		if limit > maxListedObjects {
			limit = maxListedObjects
		}
		for _, change := range report.Diff.Indexes[:limit] {
			switch change.Kind {
			case "add":
				fmt.Fprintf(writer, "  + [%s] %s -> %s\n", change.Index, change.Key, change.After)
			case "remove":
				fmt.Fprintf(writer, "  - [%s] %s (was %s)\n", change.Index, change.Key, change.Before)
			default:
				fmt.Fprintf(writer, "  ~ [%s] %s: %s -> %s\n", change.Index, change.Key, change.Before, change.After)
			}
		}
		if remaining := len(report.Diff.Indexes) - limit; remaining > 0 {
			fmt.Fprintf(writer, "  ... and %d more\n", remaining)
		}
	}

	if report.HasFindings() {
		fmt.Fprintln(writer)
		totals := report.FindingCounts()
		fmt.Fprintf(writer, "Validation findings: %d (format=%d reference=%d index=%d summary=%d)\n",
			len(report.Findings),
			totals[recovery.CategoryFormat], totals[recovery.CategoryReference],
			totals[recovery.CategoryIndex], totals[recovery.CategorySummary])
		for _, finding := range report.Findings {
			fmt.Fprintf(writer, "  - %s\n", finding.String())
		}
	}

	fmt.Fprintln(writer)
	fmt.Fprintf(writer, "status: %s\n", report.Outcome)
	if report.Message != "" {
		fmt.Fprintf(writer, "  %s\n", report.Message)
	}
}

func listObjects(writer io.Writer, label string, objects []recovery.ObjectSummary) {
	if len(objects) == 0 {
		return
	}
	limit := len(objects)
	if limit > maxListedObjects {
		limit = maxListedObjects
	}
	fmt.Fprintf(writer, "%s:\n", label)
	for _, object := range objects[:limit] {
		fmt.Fprintf(writer, "  %s  %-12s %s\n", object.ID, object.Type, object.Descriptor)
	}
	if remaining := len(objects) - limit; remaining > 0 {
		fmt.Fprintf(writer, "  ... and %d more\n", remaining)
	}
}
