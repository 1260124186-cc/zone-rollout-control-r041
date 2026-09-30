package restore

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"solo-0014-zone-rollout-control/internal/domain"
	"solo-0014-zone-rollout-control/internal/platform"
	"solo-0014-zone-rollout-control/internal/store"
)

const reportVersion = 1

// Run executes the offline restore command. It never dials a service: the
// candidate and the target are plain files, and the target lock file keeps
// a running service's state out of reach. The JSON report is written to
// stdout on every outcome after the candidate could be read.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("zrcrestore", flag.ContinueOnError)
	flags.SetOutput(stderr)
	snapshotPath := flags.String("snapshot", "", "candidate snapshot path to validate and restore (required)")
	targetPath := flags.String("target", "", "target state path the candidate is restored to (required)")
	apply := flags.Bool("apply", false, "atomically replace the target after validation and confirmation")
	yes := flags.Bool("yes", false, "confirm the restore non-interactively instead of prompting")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: zrcrestore --snapshot <candidate.json> --target <state.json> [--apply] [--yes]")
		fmt.Fprintln(stderr, "without --apply the command validates the candidate and prints the objects it")
		fmt.Fprintln(stderr, "would initialize, replace, or remove; with --apply it atomically writes the")
		fmt.Fprintln(stderr, "restored state snapshot after explicit confirmation (--yes or prompt)")
		fmt.Fprintln(stderr, "the command never connects to a running service; it refuses to operate")
		fmt.Fprintln(stderr, "while the target lock file is held")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *snapshotPath == "" || *targetPath == "" {
		flags.Usage()
		return errors.New("both --snapshot and --target are required")
	}
	if *yes && !*apply {
		return errors.New("--yes only makes sense together with --apply")
	}
	candidatePath, err := filepath.Abs(*snapshotPath)
	if err != nil {
		return fmt.Errorf("resolve candidate path: %w", err)
	}
	resolvedTarget, err := filepath.Abs(*targetPath)
	if err != nil {
		return fmt.Errorf("resolve target path: %w", err)
	}
	if candidatePath == resolvedTarget {
		return errors.New("candidate and target must be different files")
	}

	mode := "validate"
	if *apply {
		mode = "apply"
	}
	report := Report{
		ReportVersion: reportVersion,
		GeneratedAt:   time.Now().UTC(),
		Mode:          mode,
		Candidate:     SnapshotInfo{Path: candidatePath},
		Target:        SnapshotInfo{Path: resolvedTarget},
	}

	payload, err := os.ReadFile(candidatePath)
	if err != nil {
		return fmt.Errorf("read candidate snapshot: %w", err)
	}
	report.Candidate.Exists = true
	candidateState, checks := validateSnapshot(payload)
	report.Validation = Validation{Valid: allPassed(checks), Checks: checks}
	if !report.Validation.Valid {
		report.Disposition = DispositionRejected
		report.Message = "candidate snapshot failed validation; the target was not touched"
		emit(stdout, report)
		return errors.New("candidate snapshot failed validation")
	}
	candidateState = store.Normalize(candidateState)
	candidateDigest, err := digestOf(candidateState)
	if err != nil {
		return fmt.Errorf("digest candidate snapshot: %w", err)
	}
	candidateCounts := CountsOf(candidateState)
	report.Candidate.Readable = true
	report.Candidate.Digest = candidateDigest
	report.Candidate.Counts = &candidateCounts

	// The target lock keeps a running service's state out of reach. Both
	// validation diffs and the apply step require it, so the command never
	// operates on a live snapshot. The target directory is created first
	// so an initialize-restore onto a not-yet-existing path can take the
	// lock and write the file.
	if err := os.MkdirAll(filepath.Dir(resolvedTarget), 0o750); err != nil {
		return fmt.Errorf("prepare target directory: %w", err)
	}
	lock, err := platform.LockFile(resolvedTarget + ".lock")
	if err != nil {
		if errors.Is(err, platform.ErrAlreadyLocked) {
			report.Message = "target state is locked by a running service"
			emit(stdout, report)
			return fmt.Errorf("target state %s is locked by a running service; stop the service before restoring", resolvedTarget)
		}
		return fmt.Errorf("lock target state: %w", err)
	}
	defer lock.Unlock()

	targetState, targetInfo := loadTarget(resolvedTarget)
	report.Target = targetInfo
	report.Disposition = dispositionOf(targetInfo, candidateDigest)
	current := domain.State{}
	if targetInfo.Readable {
		current = targetState
	}
	report.Diff = diffStates(candidateState, store.Normalize(current))

	if !*apply {
		report.Confirmation = ConfirmationNotRequested
		emit(stdout, report)
		return nil
	}
	if report.Disposition == DispositionIdentical {
		report.Confirmation = ConfirmationNotRequested
		report.Message = "target already matches the candidate; nothing to write"
		emit(stdout, report)
		return nil
	}

	if !*yes {
		confirmed, err := promptConfirmation(stdin, stderr, resolvedTarget, report.Disposition)
		if err != nil {
			return err
		}
		if !confirmed {
			report.Confirmation = ConfirmationPromptDeclined
			report.Message = "restore was not confirmed; the target was not touched"
			emit(stdout, report)
			return errors.New("restore was not confirmed")
		}
		report.Confirmation = ConfirmationPromptAccepted
	} else {
		report.Confirmation = ConfirmationFlag
	}

	if err := store.PersistSnapshot(resolvedTarget, candidateState); err != nil {
		report.Message = "write failed; the original target file was preserved"
		emit(stdout, report)
		return fmt.Errorf("write restored snapshot: %w", err)
	}
	report.Applied = true

	verified, err := verifyWritten(resolvedTarget, candidateDigest)
	if err != nil {
		report.Message = "post-write verification failed"
		emit(stdout, report)
		return fmt.Errorf("verify restored snapshot: %w", err)
	}
	report.Verified = verified
	report.Message = "restore applied; startup will read the reported counts"
	emit(stdout, report)
	return nil
}

// loadTarget reads the target leniently. A missing target is a fresh
// restore; an unreadable one is treated as a conflict so the operator can
// still replace a corrupted file.
func loadTarget(path string) (domain.State, SnapshotInfo) {
	info := SnapshotInfo{Path: path}
	payload, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return domain.State{}, info
	}
	info.Exists = true
	if err != nil {
		return domain.State{}, info
	}
	var state domain.State
	if err := json.Unmarshal(payload, &state); err != nil {
		return domain.State{}, info
	}
	state = store.Normalize(state)
	digest, err := digestOf(state)
	if err != nil {
		return domain.State{}, info
	}
	counts := CountsOf(state)
	info.Readable = true
	info.Digest = digest
	info.Counts = &counts
	return state, info
}

func dispositionOf(target SnapshotInfo, candidateDigest string) string {
	if !target.Exists {
		return DispositionInitialize
	}
	if target.Readable && target.Digest == candidateDigest {
		return DispositionIdentical
	}
	return DispositionConflict
}

func promptConfirmation(stdin io.Reader, stderr io.Writer, target string, disposition string) (bool, error) {
	fmt.Fprintf(stderr, "restore will %s the target state %s\n", describeDisposition(disposition), target)
	fmt.Fprintln(stderr, "type 'restore' to confirm:")
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	return strings.TrimSpace(line) == "restore", nil
}

func describeDisposition(disposition string) string {
	if disposition == DispositionInitialize {
		return "initialize"
	}
	return "replace"
}

// verifyWritten re-reads the target from disk and confirms it decodes to
// the candidate state, so the counts a starting service reads are exactly
// the counts the report announced.
func verifyWritten(path string, candidateDigest string) (bool, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read restored snapshot: %w", err)
	}
	var state domain.State
	if err := json.Unmarshal(payload, &state); err != nil {
		return false, fmt.Errorf("decode restored snapshot: %w", err)
	}
	digest, err := digestOf(store.Normalize(state))
	if err != nil {
		return false, fmt.Errorf("digest restored snapshot: %w", err)
	}
	if digest != candidateDigest {
		return false, errors.New("restored snapshot digest does not match the candidate")
	}
	return true, nil
}

func emit(stdout io.Writer, report Report) {
	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return
	}
	_, _ = stdout.Write(append(payload, '\n'))
}
