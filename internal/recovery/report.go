package recovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"solo-0014-zone-rollout-control/internal/domain"
	"solo-0014-zone-rollout-control/internal/store"
)

// Identity classifies the relation between a candidate snapshot and the
// snapshot currently stored at the target location.
type Identity string

const (
	// IdentityNew means no readable target snapshot exists.
	IdentityNew Identity = "new"
	// IdentitySame means target and candidate are canonical-identical.
	IdentitySame Identity = "same"
	// IdentityConflict means target and candidate are different snapshots.
	IdentityConflict Identity = "conflict"
)

// Outcome of the report stage, mirrored in the final status line.
type Outcome string

const (
	OutcomeReady       Outcome = "ready"
	OutcomeInvalid     Outcome = "invalid"
	OutcomeIdentical   Outcome = "identical"
	OutcomeBlocked     Outcome = "blocked"
	OutcomeRestored    Outcome = "restored"
	OutcomeLocked      Outcome = "locked"
	OutcomeWriteFailed Outcome = "write_failed"
)

// Counts summarizes entity totals after recovery; these are exactly the
// counters a subsequent service startup will load.
type Counts struct {
	Plans           int `json:"plans"`
	Revisions       int `json:"revisions"`
	Nodes           int `json:"nodes"`
	Leases          int `json:"leases"`
	LeaseGroups     int `json:"lease_groups"`
	Probes          int `json:"probes"`
	Assessments     int `json:"assessments"`
	AuditEvents     int `json:"audit_events"`
	LeaseIndexKeys  int `json:"lease_request_index"`
	AssessmentIndex int `json:"assessment_request_index"`
}

func countState(state *domain.State) Counts {
	return Counts{
		Plans:           len(state.Plans),
		Revisions:       len(state.Revisions),
		Nodes:           len(state.Nodes),
		Leases:          len(state.Leases),
		LeaseGroups:     len(state.LeaseGroups),
		Probes:          len(state.Probes),
		Assessments:     len(state.Assessments),
		AuditEvents:     len(state.AuditEvents),
		LeaseIndexKeys:  len(state.LeaseRequestKeys),
		AssessmentIndex: len(state.AssessmentRequestKeys),
	}
}

// ObjectSummary is one object the recovery would add or replace.
type ObjectSummary struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Descriptor string `json:"descriptor"`
}

// ChangeSet describes object-level differences between target and candidate.
type ChangeSet struct {
	Replace []ObjectSummary `json:"replace"`
	Add     []ObjectSummary `json:"add"`
	Remove  []ObjectSummary `json:"remove"`
}

func (s ChangeSet) empty() bool {
	return len(s.Replace) == 0 && len(s.Add) == 0 && len(s.Remove) == 0
}

// IndexChange describes one idempotency index entry that would change.
type IndexChange struct {
	Index  string `json:"index"`
	Key    string `json:"key"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
	Kind   string `json:"kind"`
}

// Diff is the full target-vs-candidate comparison shown in the report.
type Diff struct {
	Identity  Identity      `json:"identity"`
	Target    Counts        `json:"target_counts"`
	Candidate Counts        `json:"candidate_counts"`
	Objects   ChangeSet     `json:"objects"`
	Indexes   []IndexChange `json:"indexes"`
}

// Report is the deterministic offline recovery report. It is rendered for
// human review and emitted as JSON with --report json.
type Report struct {
	CandidatePath   string    `json:"candidate_path"`
	TargetPath      string    `json:"target_path"`
	CandidateDigest string    `json:"candidate_sha256"`
	CandidateBytes  int64     `json:"candidate_bytes"`
	TargetDigest    string    `json:"target_sha256,omitempty"`
	TargetPresent   bool      `json:"target_present"`
	TargetReadable  bool      `json:"target_readable"`
	SchemaVersion   int       `json:"schema_version"`
	StateRevision   uint64    `json:"state_revision"`
	Counts          Counts    `json:"counts"`
	Findings        []Finding `json:"findings"`
	Diff            Diff      `json:"diff"`
	Outcome         Outcome   `json:"outcome"`
	Confirmed       bool      `json:"confirmed"`
	Force           bool      `json:"force"`
	Message         string    `json:"message,omitempty"`
}

func (r *Report) HasFindings() bool { return len(r.Findings) > 0 }

func (r *Report) FindingCounts() map[FindingCategory]int {
	counts := map[FindingCategory]int{}
	for _, finding := range r.Findings {
		counts[finding.Category]++
	}
	return counts
}

// Options controls a recovery run.
type Options struct {
	CandidatePath string
	TargetPath    string
	Confirm       bool
	Force         bool
}

// LoadCandidate reads and strictly decodes a candidate snapshot from disk.
// The boolean reports whether the file exists; decode problems are returned
// as findings so every malformed candidate produces a full report instead of
// an opaque error.
func LoadCandidate(path string) (domain.State, []byte, []Finding, bool, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return domain.State{}, nil, nil, false, nil
		}
		return domain.State{}, nil, nil, false, fmt.Errorf("read candidate snapshot: %w", err)
	}
	state, decodeErr := store.StrictDecodeState(payload)
	if decodeErr != nil {
		return domain.State{}, payload, []Finding{{
			Category: CategoryFormat,
			Code:     "undecodable_snapshot",
			Message:  decodeErr.Error(),
		}}, true, nil
	}
	return state, payload, nil, true, nil
}

// canonicalDigest renders the normalized state exactly the way the service
// persists it, then hashes it. Two snapshots that are canonical-identical
// survive repeated recovery as "same" even if their source formatting
// differs.
func canonicalDigest(state *domain.State) (string, []byte, error) {
	encoded, err := store.EncodeSnapshot(state)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), encoded, nil
}

func payloadSHA256(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// DiffStates compares a target snapshot against the candidate without any
// network or service involvement.
func DiffStates(target *domain.State, candidate *domain.State) Diff {
	diff := Diff{
		Identity:  IdentityConflict,
		Candidate: countState(candidate),
	}
	if target == nil {
		diff.Identity = IdentityNew
	} else {
		diff.Target = countState(target)
	}

	type entry struct {
		kind       string
		id         string
		before     string
		after      string
		descriptor string
	}
	var entries []entry

	collect := func(kind string, id, before, after, descriptor string) {
		entries = append(entries, entry{kind, id, before, after, descriptor})
	}

	// Entity collections keyed by id.
	planDescriptor := func(plan domain.RolloutPlan) string {
		return fmt.Sprintf("zone=%s state=%s version=%d", plan.Zone, plan.State, plan.Version)
	}
	revisionDescriptor := func(revision domain.ZoneRevision) string {
		return fmt.Sprintf("plan=%s serial=%d entries=%d", revision.PlanID, revision.Serial, revision.EntryCount)
	}
	nodeDescriptor := func(node domain.ResolverNode) string {
		return fmt.Sprintf("name=%s region=%s state=%s", node.NodeName, node.Region, node.State)
	}
	leaseDescriptor := func(lease domain.NodeLease) string {
		return fmt.Sprintf("plan=%s node=%s state=%s", lease.PlanID, lease.NodeID, lease.State)
	}
	groupDescriptor := func(group domain.LeaseGroup) string {
		return fmt.Sprintf("plan=%s key=%s leases=%d", group.PlanID, group.RequestKey, len(group.LeaseIDs))
	}
	probeDescriptor := func(probe domain.Probe) string {
		return fmt.Sprintf("lease=%s success=%t latency=%d", probe.LeaseID, probe.Success, probe.LatencyMS)
	}
	assessmentDescriptor := func(assessment domain.RolloutAssessment) string {
		return fmt.Sprintf("plan=%s verdict=%s probes=%d", assessment.PlanID, assessment.Verdict, assessment.ProbeCount)
	}

	if target == nil {
		for id, value := range candidate.Plans {
			collect("plan", id, "", canonicalJSON(value), planDescriptor(value))
		}
		for id, value := range candidate.Revisions {
			collect("revision", id, "", canonicalJSON(value), revisionDescriptor(value))
		}
		for id, value := range candidate.Nodes {
			collect("node", id, "", canonicalJSON(value), nodeDescriptor(value))
		}
		for id, value := range candidate.Leases {
			collect("lease", id, "", canonicalJSON(value), leaseDescriptor(value))
		}
		for id, value := range candidate.LeaseGroups {
			collect("lease_group", id, "", canonicalJSON(value), groupDescriptor(value))
		}
		for id, value := range candidate.Probes {
			collect("probe", id, "", canonicalJSON(value), probeDescriptor(value))
		}
		for id, value := range candidate.Assessments {
			collect("assessment", id, "", canonicalJSON(value), assessmentDescriptor(value))
		}
	} else {
		compareMaps(target.Plans, candidate.Plans, "plan", planDescriptor, collect)
		compareMaps(target.Revisions, candidate.Revisions, "revision", revisionDescriptor, collect)
		compareMaps(target.Nodes, candidate.Nodes, "node", nodeDescriptor, collect)
		compareMaps(target.Leases, candidate.Leases, "lease", leaseDescriptor, collect)
		compareMaps(target.LeaseGroups, candidate.LeaseGroups, "lease_group", groupDescriptor, collect)
		compareMaps(target.Probes, candidate.Probes, "probe", probeDescriptor, collect)
		compareMaps(target.Assessments, candidate.Assessments, "assessment", assessmentDescriptor, collect)
	}

	// Audit events are append-only history; diff by id set.
	targetAudit := map[string]struct{}{}
	if target != nil {
		for _, event := range target.AuditEvents {
			targetAudit[event.ID] = struct{}{}
		}
	}
	for _, event := range candidate.AuditEvents {
		descriptor := fmt.Sprintf("entity=%s action=%s", event.EntityType, event.Action)
		if _, ok := targetAudit[event.ID]; ok {
			continue
		}
		before := ""
		if target != nil {
			before = "missing"
		}
		collect("audit_event", event.ID, before, canonicalJSON(event), descriptor)
	}
	if target != nil {
		candidateAudit := map[string]struct{}{}
		for _, event := range candidate.AuditEvents {
			candidateAudit[event.ID] = struct{}{}
		}
		for id := range targetAudit {
			if _, ok := candidateAudit[id]; !ok {
				collect("audit_event", id, "present", "", "")
			}
		}
	}

	// Idempotency index maps.
	indexDiff := func(indexName string, before, after map[string]string) {
		keys := make(map[string]struct{}, len(before)+len(after))
		for key := range before {
			keys[key] = struct{}{}
		}
		for key := range after {
			keys[key] = struct{}{}
		}
		for key := range keys {
			b, bOK := before[key]
			a, aOK := after[key]
			switch {
			case bOK && aOK && b != a:
				diff.Indexes = append(diff.Indexes, IndexChange{Index: indexName, Key: key, Before: b, After: a, Kind: "replace"})
			case !bOK && aOK:
				diff.Indexes = append(diff.Indexes, IndexChange{Index: indexName, Key: key, After: a, Kind: "add"})
			case bOK && !aOK:
				diff.Indexes = append(diff.Indexes, IndexChange{Index: indexName, Key: key, Before: b, Kind: "remove"})
			}
		}
	}
	var beforeLease, beforeAssessment map[string]string
	if target != nil {
		beforeLease = target.LeaseRequestKeys
		beforeAssessment = target.AssessmentRequestKeys
	}
	indexDiff("lease_request_keys", beforeLease, candidate.LeaseRequestKeys)
	indexDiff("assessment_request_keys", beforeAssessment, candidate.AssessmentRequestKeys)

	for _, item := range entries {
		summary := ObjectSummary{Type: item.kind, ID: item.id, Descriptor: item.descriptor}
		switch {
		case item.before == "" && item.after != "":
			diff.Objects.Add = append(diff.Objects.Add, summary)
		case item.before != "" && item.after == "":
			diff.Objects.Remove = append(diff.Objects.Remove, summary)
		default:
			diff.Objects.Replace = append(diff.Objects.Replace, summary)
		}
	}
	sortSummaries(diff.Objects.Add)
	sortSummaries(diff.Objects.Replace)
	sortSummaries(diff.Objects.Remove)
	sort.Slice(diff.Indexes, func(i, j int) bool {
		if diff.Indexes[i].Index != diff.Indexes[j].Index {
			return diff.Indexes[i].Index < diff.Indexes[j].Index
		}
		return diff.Indexes[i].Key < diff.Indexes[j].Key
	})

	if target != nil && len(entries) == 0 && len(diff.Indexes) == 0 {
		diff.Identity = IdentitySame
	}
	return diff
}

func compareMaps[T any](
	before map[string]T,
	after map[string]T,
	kind string,
	descriptor func(T) string,
	collect func(kind, id, before, after, descriptor string),
) {
	for id, candidateValue := range after {
		candidateJSON := canonicalJSON(candidateValue)
		targetValue, ok := before[id]
		if !ok {
			collect(kind, id, "", candidateJSON, descriptor(candidateValue))
			continue
		}
		if canonicalJSON(targetValue) != candidateJSON {
			collect(kind, id, canonicalJSON(targetValue), candidateJSON, descriptor(candidateValue))
		}
	}
	for id, targetValue := range before {
		if _, ok := after[id]; !ok {
			collect(kind, id, canonicalJSON(targetValue), "", descriptor(targetValue))
		}
	}
}

func canonicalJSON(value any) string {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	if err := encoder.Encode(value); err != nil {
		return ""
	}
	return buffer.String()
}

func sortSummaries(items []ObjectSummary) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Type != items[j].Type {
			return items[i].Type < items[j].Type
		}
		return items[i].ID < items[j].ID
	})
}
