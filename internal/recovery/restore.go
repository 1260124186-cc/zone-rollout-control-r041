package recovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"solo-0014-zone-rollout-control/internal/domain"
	"solo-0014-zone-rollout-control/internal/platform"
	"solo-0014-zone-rollout-control/internal/store"
)

// ErrLocked means another process (normally the running zrc service) holds
// the target snapshot lock; recovery refuses to proceed.
var ErrLocked = errors.New("target snapshot is locked by another process; stop the service before offline recovery")

// Plan performs the complete offline analysis without modifying anything:
// it strictly decodes the candidate, runs all validation stages, compares
// against the current target and classifies identity for repeat-recovery
// detection. It never opens a network connection.
func Plan(options Options) (*Report, error) {
	return planLocked(options, nil)
}

// planLocked builds the report. An optional live lock signals that the
// target file lock is already held for the apply phase.
func planLocked(options Options, heldLock *platform.FileLock) (*Report, error) {
	candidate, rawPayload, decodeFindings, exists, err := LoadCandidate(options.CandidatePath)
	if err != nil {
		return nil, err
	}
	report := &Report{
		CandidatePath:  options.CandidatePath,
		TargetPath:     options.TargetPath,
		CandidateBytes: int64(len(rawPayload)),
		Confirmed:      options.Confirm,
		Force:          options.Force,
		Findings:       []Finding{},
	}
	if len(decodeFindings) > 0 {
		report.Findings = decodeFindings
	}
	if !exists {
		return nil, fmt.Errorf("candidate snapshot not found: %s", options.CandidatePath)
	}
	report.CandidateDigest = payloadSHA256(rawPayload)

	// Target analysis: missing is normal for first restore, unreadable is
	// reported but never blocks validation of the candidate.
	targetPayload, readErr := os.ReadFile(options.TargetPath)
	report.TargetPresent = readErr == nil
	if readErr == nil {
		report.TargetDigest = payloadSHA256(targetPayload)
		var target domain.State
		if err := json.Unmarshal(targetPayload, &target); err == nil {
			report.TargetReadable = true
			target = store.Normalize(target)
			if len(decodeFindings) == 0 {
				report.Diff = DiffStates(&target, &candidate)
			} else {
				report.Diff = Diff{Identity: IdentityConflict, Candidate: countState(&candidate), Target: countState(&target)}
			}
		} else {
			report.TargetReadable = false
			report.Diff = Diff{Identity: IdentityConflict, Candidate: countState(&candidate)}
			report.Findings = append(report.Findings, Finding{
				Category: CategoryFormat,
				Code:     "target_undecodable",
				Message:  "existing target snapshot cannot be decoded; restore would replace it",
				Ref:      options.TargetPath,
			})
		}
	} else if errors.Is(readErr, os.ErrNotExist) {
		report.Diff = DiffStates(nil, &candidate)
	} else {
		return nil, fmt.Errorf("read target snapshot: %w", readErr)
	}

	if len(decodeFindings) == 0 {
		report.Findings = append(report.Findings, Validate(&candidate)...)
	}
	report.SchemaVersion = candidate.SchemaVersion
	report.StateRevision = candidate.Revision
	report.Counts = countState(&candidate)

	switch {
	case len(report.Findings) > 0:
		report.Outcome = OutcomeInvalid
		report.Message = "candidate snapshot failed offline verification; no files were changed"
	case report.Diff.Identity == IdentitySame:
		report.Outcome = OutcomeIdentical
		report.Message = "target already contains this exact snapshot; nothing to restore"
	case !options.Confirm:
		report.Outcome = OutcomeReady
		report.Message = "verification passed; re-run with --confirm to atomically write the target snapshot"
	case options.Force || report.Diff.Identity != IdentityConflict:
		report.Outcome = OutcomeReady
	default:
		report.Outcome = OutcomeBlocked
		report.Message = "target contains a different snapshot; re-run with --force to replace it"
	}
	_ = heldLock
	return report, nil
}

// Apply runs the confirmed restore. It acquires the same flock the running
// service uses (non-blocking, so a live service is detected instead of
// raced), replans under the lock, atomically replaces the target and
// immediately re-reads it through the strict path to prove the startup
// counters match the report. On any failure the original file is retained.
func Apply(options Options) (*Report, error) {
	if !options.Confirm {
		return Plan(options)
	}
	// Acquire the same flock the running service uses, non-blocking, so a
	// live service is detected instead of raced. A lightweight probe of
	// the candidate is recorded for the locked report.
	locked := false
	lock, err := platform.LockFile(options.TargetPath + ".lock")
	if err != nil {
		if !errors.Is(err, platform.ErrAlreadyLocked) {
			return nil, fmt.Errorf("lock target snapshot: %w", err)
		}
		locked = true
	} else {
		defer func() { _ = lock.Unlock() }()
	}

	report, err := planLocked(options, lock)
	if err != nil {
		return nil, err
	}
	if locked {
		report.Outcome = OutcomeLocked
		report.Message = ErrLocked.Error()
		report.Confirmed = true
		return report, ErrLocked
	}

	switch report.Outcome {
	case OutcomeInvalid, OutcomeBlocked, OutcomeIdentical:
		return report, nil
	case OutcomeReady:
	default:
		return report, nil
	}

	candidate, _, decodeFindings, exists, err := LoadCandidate(options.CandidatePath)
	if err != nil || !exists || len(decodeFindings) > 0 {
		report.Outcome = OutcomeInvalid
		report.Message = "candidate snapshot changed and no longer passes verification"
		return report, nil
	}

	digest, encoded, err := canonicalDigest(&candidate)
	if err != nil {
		return nil, err
	}

	// Preserve the existing file mode on replacement so recovery does not
	// change target permissions.
	mode := os.FileMode(0o600)
	if info, statErr := os.Stat(options.TargetPath); statErr == nil {
		mode = info.Mode().Perm()
	}

	if writeErr := store.ReplacePayload(options.TargetPath, encoded, mode); writeErr != nil {
		report.Outcome = OutcomeWriteFailed
		report.Message = "atomic write failed; original target snapshot was retained: " + writeErr.Error()
		return report, writeErr
	}

	// Post-write verification through the exact strict load path: the
	// counters reported here are what the service startup will read.
	reloadedPayload, err := os.ReadFile(options.TargetPath)
	if err != nil {
		report.Outcome = OutcomeWriteFailed
		report.Message = "reload after restore failed: " + err.Error()
		return report, err
	}
	reloaded, err := store.StrictDecodeState(reloadedPayload)
	if err != nil {
		report.Outcome = OutcomeWriteFailed
		report.Message = "reloaded snapshot failed strict verification: " + err.Error()
		return report, err
	}
	reloadedDigest, _, err := canonicalDigest(&reloaded)
	if err != nil || reloadedDigest != digest {
		report.Outcome = OutcomeWriteFailed
		report.Message = "reloaded snapshot fingerprint does not match candidate"
		return report, fmt.Errorf("post-restore fingerprint mismatch")
	}
	if findings := Validate(&reloaded); len(findings) > 0 {
		report.Outcome = OutcomeWriteFailed
		report.Findings = findings
		report.Message = "reloaded snapshot failed validation"
		return report, fmt.Errorf("post-restore validation failed")
	}
	report.Counts = countState(&reloaded)
	report.TargetPresent = true
	report.TargetReadable = true
	report.TargetDigest = payloadSHA256(reloadedPayload)
	report.Diff = DiffStates(&candidate, &reloaded)
	report.Outcome = OutcomeRestored
	report.Message = "restore complete; target now contains the verified snapshot"
	return report, nil
}
