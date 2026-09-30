package restore

import (
	"time"

	"solo-0014-zone-rollout-control/internal/domain"
)

// Check group names reported for candidate validation.
const (
	CheckFormat     = "format"
	CheckReferences = "references"
	CheckIndexes    = "idempotency_indexes"
	CheckDigests    = "digests"
)

// Check statuses.
const (
	StatusPassed = "passed"
	StatusFailed = "failed"
)

// Disposition describes how the candidate relates to the target.
const (
	DispositionInitialize = "initialize"
	DispositionIdentical  = "identical"
	DispositionConflict   = "conflict"
	DispositionRejected   = "rejected"
)

// Confirmation records how the apply step was confirmed.
const (
	ConfirmationNotRequested   = "not_requested"
	ConfirmationFlag           = "flag"
	ConfirmationPromptAccepted = "prompt_accepted"
	ConfirmationPromptDeclined = "prompt_declined"
)

// Counts lists how many objects of each collection a snapshot holds. These
// are exactly the counts the service observes when it opens the snapshot.
type Counts struct {
	Plans                 int `json:"plans"`
	Revisions             int `json:"revisions"`
	Nodes                 int `json:"nodes"`
	Leases                int `json:"leases"`
	LeaseGroups           int `json:"lease_groups"`
	Probes                int `json:"probes"`
	Assessments           int `json:"assessments"`
	LeaseRequestKeys      int `json:"lease_request_keys"`
	AssessmentRequestKeys int `json:"assessment_request_keys"`
	AuditEvents           int `json:"audit_events"`
}

// CountsOf tallies every collection of a state.
func CountsOf(state domain.State) Counts {
	return Counts{
		Plans:                 len(state.Plans),
		Revisions:             len(state.Revisions),
		Nodes:                 len(state.Nodes),
		Leases:                len(state.Leases),
		LeaseGroups:           len(state.LeaseGroups),
		Probes:                len(state.Probes),
		Assessments:           len(state.Assessments),
		LeaseRequestKeys:      len(state.LeaseRequestKeys),
		AssessmentRequestKeys: len(state.AssessmentRequestKeys),
		AuditEvents:           len(state.AuditEvents),
	}
}

// Finding is a single validation problem tied to a check group.
type Finding struct {
	Check   string `json:"check"`
	Entity  string `json:"entity,omitempty"`
	ID      string `json:"id,omitempty"`
	Message string `json:"message"`
}

// CheckResult aggregates the findings of one check group.
type CheckResult struct {
	Name     string    `json:"name"`
	Status   string    `json:"status"`
	Findings []Finding `json:"findings,omitempty"`
}

// Validation summarizes the candidate checks.
type Validation struct {
	Valid  bool          `json:"valid"`
	Checks []CheckResult `json:"checks"`
}

// EntityDiff summarizes how one collection differs between candidate and
// target. Identifier lists are capped; counts stay exact.
type EntityDiff struct {
	Added       int      `json:"added"`
	Replaced    int      `json:"replaced"`
	Unchanged   int      `json:"unchanged"`
	Removed     int      `json:"removed"`
	AddedIDs    []string `json:"added_ids,omitempty"`
	ReplacedIDs []string `json:"replaced_ids,omitempty"`
	RemovedIDs  []string `json:"removed_ids,omitempty"`
	Truncated   bool     `json:"truncated,omitempty"`
}

// Diff summarizes, per collection, which objects a restore would add,
// replace, or remove.
type Diff struct {
	Plans                 EntityDiff `json:"plans"`
	Revisions             EntityDiff `json:"revisions"`
	Nodes                 EntityDiff `json:"nodes"`
	Leases                EntityDiff `json:"leases"`
	LeaseGroups           EntityDiff `json:"lease_groups"`
	Probes                EntityDiff `json:"probes"`
	Assessments           EntityDiff `json:"assessments"`
	LeaseRequestKeys      EntityDiff `json:"lease_request_keys"`
	AssessmentRequestKeys EntityDiff `json:"assessment_request_keys"`
	AuditEvents           EntityDiff `json:"audit_events"`
}

// SnapshotInfo describes one snapshot file.
type SnapshotInfo struct {
	Path     string  `json:"path"`
	Exists   bool    `json:"exists"`
	Readable bool    `json:"readable"`
	Digest   string  `json:"digest,omitempty"`
	Counts   *Counts `json:"counts,omitempty"`
}

// Report is the machine-readable outcome of a restore run. It is always
// written to stdout, including for declined or failed runs.
type Report struct {
	ReportVersion int          `json:"report_version"`
	GeneratedAt   time.Time    `json:"generated_at"`
	Mode          string       `json:"mode"`
	Candidate     SnapshotInfo `json:"candidate"`
	Target        SnapshotInfo `json:"target"`
	Validation    Validation   `json:"validation"`
	Diff          *Diff        `json:"diff,omitempty"`
	Disposition   string       `json:"disposition"`
	Confirmation  string       `json:"confirmation,omitempty"`
	Applied       bool         `json:"applied"`
	Verified      bool         `json:"verified"`
	Message       string       `json:"message,omitempty"`
}
