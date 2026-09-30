package restore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"time"

	"solo-0014-zone-rollout-control/internal/domain"
)

const supportedSchemaVersion = 1

var requiredTopLevelKeys = []string{
	"schema_version",
	"revision",
	"plans",
	"revisions",
	"nodes",
	"leases",
	"lease_groups",
	"probes",
	"assessments",
	"lease_request_keys",
	"assessment_request_keys",
	"audit_events",
}

var knownReasonCodes = map[string]struct{}{
	"no_probes":                   {},
	"node_not_observed":           {},
	"serial_mismatch":             {},
	"success_ratio_below_minimum": {},
	"latency_limit_exceeded":      {},
}

// validateSnapshot decodes a candidate snapshot and runs every check group.
// The returned state is only meaningful when all checks passed.
func validateSnapshot(payload []byte) (domain.State, []CheckResult) {
	var state domain.State
	formatFindings := make([]Finding, 0)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		formatFindings = append(formatFindings, Finding{
			Check:   CheckFormat,
			Message: "snapshot is not a JSON object: " + err.Error(),
		})
		return state, checkResults(formatFindings, nil, nil, nil)
	}
	for _, key := range requiredTopLevelKeys {
		if _, ok := raw[key]; !ok {
			formatFindings = append(formatFindings, Finding{
				Check:   CheckFormat,
				Message: "missing top-level key " + key,
			})
		}
	}
	if path, dup := duplicatedJSONKey(payload); dup {
		formatFindings = append(formatFindings, Finding{
			Check:   CheckFormat,
			Message: "duplicate JSON key " + path + " is ambiguous",
		})
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		formatFindings = append(formatFindings, Finding{
			Check:   CheckFormat,
			Message: "snapshot does not match the state schema: " + err.Error(),
		})
		return state, checkResults(formatFindings, nil, nil, nil)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		formatFindings = append(formatFindings, Finding{
			Check:   CheckFormat,
			Message: "unexpected data after the JSON document",
		})
	}
	if state.SchemaVersion != supportedSchemaVersion {
		formatFindings = append(formatFindings, Finding{
			Check:   CheckFormat,
			Message: fmt.Sprintf("schema_version %d is not supported, expected %d", state.SchemaVersion, supportedSchemaVersion),
		})
	}
	formatFindings = append(formatFindings, checkCollectionsPresent(state)...)
	formatFindings = append(formatFindings, checkEntityFormat(state)...)

	return state, checkResults(
		formatFindings,
		checkReferences(state),
		checkIndexes(state),
		checkDigests(state),
	)
}

func checkResults(format, references, indexes, digests []Finding) []CheckResult {
	return []CheckResult{
		namedResult(CheckFormat, format),
		namedResult(CheckReferences, references),
		namedResult(CheckIndexes, indexes),
		namedResult(CheckDigests, digests),
	}
}

func namedResult(name string, findings []Finding) CheckResult {
	for index := range findings {
		findings[index].Check = name
	}
	return CheckResult{Name: name, Status: statusOf(findings), Findings: findings}
}

func statusOf(findings []Finding) string {
	if len(findings) > 0 {
		return StatusFailed
	}
	return StatusPassed
}

func allPassed(checks []CheckResult) bool {
	for _, check := range checks {
		if check.Status != StatusPassed {
			return false
		}
	}
	return true
}

func checkCollectionsPresent(state domain.State) []Finding {
	findings := make([]Finding, 0)
	collections := []struct {
		name string
		nil_ bool
	}{
		{"plans", state.Plans == nil},
		{"revisions", state.Revisions == nil},
		{"nodes", state.Nodes == nil},
		{"leases", state.Leases == nil},
		{"lease_groups", state.LeaseGroups == nil},
		{"probes", state.Probes == nil},
		{"assessments", state.Assessments == nil},
		{"lease_request_keys", state.LeaseRequestKeys == nil},
		{"assessment_request_keys", state.AssessmentRequestKeys == nil},
		{"audit_events", state.AuditEvents == nil},
	}
	for _, collection := range collections {
		if collection.nil_ {
			findings = append(findings, Finding{
				Check:   CheckFormat,
				Message: "collection " + collection.name + " must be an empty collection, not null",
			})
		}
	}
	return findings
}

func checkEntityFormat(state domain.State) []Finding {
	findings := make([]Finding, 0)

	for _, id := range sortedKeys(state.Plans) {
		plan := state.Plans[id]
		findings = checkMapKey(findings, "plan", id, plan.ID, "pln_")
		switch plan.State {
		case domain.PlanDraft, domain.PlanActive, domain.PlanCompleted:
		default:
			findings = addFinding(findings, "plan", id, fmt.Sprintf("state %q is not a known plan state", plan.State))
		}
		if plan.Version < 1 {
			findings = addFinding(findings, "plan", id, "version must be at least 1")
		}
		input := domain.PlanCreateInput{
			Zone:                plan.Zone,
			MinimumSuccessRatio: plan.MinimumSuccessRatio,
			MaximumLatencyMS:    plan.MaximumLatencyMS,
			ExpectedNodes:       plan.ExpectedNodes,
		}
		findings = appendDomainFindings(findings, "plan", id, domain.ValidatePlanInput(input))
		if domain.NormalizePlanInput(input).Zone != plan.Zone {
			findings = addFinding(findings, "plan", id, "zone is not stored in canonical form")
		}
		if plan.CreatedAt.IsZero() {
			findings = addFinding(findings, "plan", id, "created_at is required")
		}
		switch plan.State {
		case domain.PlanDraft:
			if plan.ActivatedAt != nil {
				findings = addFinding(findings, "plan", id, "draft plan must not carry activated_at")
			}
		case domain.PlanActive, domain.PlanCompleted:
			if plan.ActivatedAt == nil {
				findings = addFinding(findings, "plan", id, "activated plan must carry activated_at")
			}
			if plan.LatestRevisionID == "" {
				findings = addFinding(findings, "plan", id, "active or completed plan must carry a zone revision")
			}
		}
		if plan.State == domain.PlanCompleted {
			if plan.CompletedAt == nil {
				findings = addFinding(findings, "plan", id, "completed plan must carry completed_at")
			}
		} else if plan.CompletedAt != nil {
			findings = addFinding(findings, "plan", id, "only a completed plan may carry completed_at")
		}
	}

	for _, id := range sortedKeys(state.Revisions) {
		revision := state.Revisions[id]
		findings = checkMapKey(findings, "revision", id, revision.ID, "rev_")
		input := domain.RevisionCreateInput{
			Serial:    revision.Serial,
			Authority: revision.Authority,
			Entries:   revision.Entries,
		}
		findings = appendDomainFindings(findings, "revision", id, domain.ValidateRevisionInput(input))
		if _, err := domain.NormalizeRevisionInput(input); err != nil {
			findings = appendDomainFindings(findings, "revision", id, err)
		}
		if revision.CreatedAt.IsZero() {
			findings = addFinding(findings, "revision", id, "created_at is required")
		}
	}

	for _, id := range sortedKeys(state.Nodes) {
		node := state.Nodes[id]
		findings = checkMapKey(findings, "node", id, node.ID, "nod_")
		switch node.State {
		case domain.NodeReady, domain.NodeLeased, domain.NodeQuarantined:
		default:
			findings = addFinding(findings, "node", id, fmt.Sprintf("state %q is not a known node state", node.State))
		}
		if node.Version < 1 {
			findings = addFinding(findings, "node", id, "version must be at least 1")
		}
		input := domain.NodeCreateInput{NodeName: node.NodeName, Region: node.Region}
		findings = appendDomainFindings(findings, "node", id, domain.ValidateNodeInput(input, node.CreatedAt))
		normalized := domain.NormalizeNodeInput(input)
		if normalized.NodeName != node.NodeName || normalized.Region != node.Region {
			findings = addFinding(findings, "node", id, "node_name and region must be stored in canonical form")
		}
		if node.CreatedAt.IsZero() || node.UpdatedAt.IsZero() {
			findings = addFinding(findings, "node", id, "created_at and updated_at are required")
		}
	}

	nodeNames := make(map[string]string, len(state.Nodes))
	for _, id := range sortedKeys(state.Nodes) {
		node := state.Nodes[id]
		if other, dup := nodeNames[node.NodeName]; dup {
			findings = addFinding(findings, "node", id,
				"node_name "+node.NodeName+" is already used by node "+other)
		}
		nodeNames[node.NodeName] = id
	}

	for _, id := range sortedKeys(state.Leases) {
		lease := state.Leases[id]
		findings = checkMapKey(findings, "lease", id, lease.ID, "lse_")
		switch lease.State {
		case domain.LeaseClaimed, domain.LeaseReported, domain.LeaseReleased, domain.LeaseExpired:
		default:
			findings = addFinding(findings, "lease", id, fmt.Sprintf("state %q is not a known lease state", lease.State))
		}
		if lease.ClaimedAt.IsZero() {
			findings = addFinding(findings, "lease", id, "claimed_at is required")
		}
		if !lease.ExpiresAt.After(lease.ClaimedAt) {
			findings = addFinding(findings, "lease", id, "expires_at must be after claimed_at")
		}
		if lease.FinishedAt != nil && lease.FinishedAt.Before(lease.ClaimedAt) {
			findings = addFinding(findings, "lease", id, "finished_at must not be before claimed_at")
		}
		switch lease.State {
		case domain.LeaseClaimed:
			if lease.FinishedAt != nil {
				findings = addFinding(findings, "lease", id, "claimed lease must not carry finished_at")
			}
			if lease.ProbeID != "" {
				findings = addFinding(findings, "lease", id, "claimed lease must not carry probe_id")
			}
		case domain.LeaseReported:
			if lease.FinishedAt == nil {
				findings = addFinding(findings, "lease", id, "reported lease must carry finished_at")
			}
			if lease.ProbeID == "" {
				findings = addFinding(findings, "lease", id, "reported lease must carry probe_id")
			}
		case domain.LeaseReleased, domain.LeaseExpired:
			if lease.FinishedAt == nil {
				findings = addFinding(findings, "lease", id, "finished lease must carry finished_at")
			}
			if lease.ProbeID != "" {
				findings = addFinding(findings, "lease", id, "only a reported lease may carry probe_id")
			}
		}
	}

	for _, id := range sortedKeys(state.LeaseGroups) {
		group := state.LeaseGroups[id]
		findings = checkMapKey(findings, "lease_group", id, group.ID, "grp_")
		findings = appendDomainFindings(findings, "lease_group", id, domain.ValidateRequestKey(group.RequestKey))
		if !isSHA256Hex(group.RequestFingerprint) {
			findings = addFinding(findings, "lease_group", id, "request_fingerprint must be a SHA-256 hex digest")
		}
		if len(group.LeaseIDs) == 0 {
			findings = addFinding(findings, "lease_group", id, "lease_ids must contain at least one lease")
		}
		seen := make(map[string]struct{}, len(group.LeaseIDs))
		for _, leaseID := range group.LeaseIDs {
			if leaseID == "" {
				findings = addFinding(findings, "lease_group", id, "lease_ids must not contain empty identifiers")
				continue
			}
			if _, dup := seen[leaseID]; dup {
				findings = addFinding(findings, "lease_group", id, "lease_ids contains duplicate "+leaseID)
			}
			seen[leaseID] = struct{}{}
		}
		if group.CreatedAt.IsZero() {
			findings = addFinding(findings, "lease_group", id, "created_at is required")
		}
	}

	for _, id := range sortedKeys(state.Probes) {
		probe := state.Probes[id]
		findings = checkMapKey(findings, "probe", id, probe.ID, "prb_")
		findings = appendDomainFindings(findings, "probe", id, domain.ValidateRequestKey(probe.RequestKey))
		if probe.LatencyMS < 0 || probe.LatencyMS > 600000 {
			findings = addFinding(findings, "probe", id, "latency_ms must be between 0 and 600000")
		}
		if probe.ObservedAt.IsZero() || probe.StoredAt.IsZero() {
			findings = addFinding(findings, "probe", id, "observed_at and stored_at are required")
		}
		if !isSHA256Hex(probe.PayloadFingerprint) {
			findings = addFinding(findings, "probe", id, "payload_fingerprint must be a SHA-256 hex digest")
		}
	}

	for _, id := range sortedKeys(state.Assessments) {
		assessment := state.Assessments[id]
		findings = checkMapKey(findings, "assessment", id, assessment.ID, "asm_")
		switch assessment.Verdict {
		case domain.VerdictConsistent, domain.VerdictReviewRequired:
		default:
			findings = addFinding(findings, "assessment", id, fmt.Sprintf("verdict %q is not a known verdict", assessment.Verdict))
		}
		for index, reason := range assessment.Reasons {
			if _, ok := knownReasonCodes[reason]; !ok {
				findings = addFinding(findings, "assessment", id, "reason "+reason+" is not a known reason code")
			}
			if index > 0 && assessment.Reasons[index-1] >= reason {
				findings = addFinding(findings, "assessment", id, "reasons must be sorted and unique")
				break
			}
		}
		if assessment.Verdict == domain.VerdictConsistent && len(assessment.Reasons) > 0 {
			findings = addFinding(findings, "assessment", id, "a consistent verdict must not carry reasons")
		}
		if assessment.Verdict == domain.VerdictReviewRequired && len(assessment.Reasons) == 0 {
			findings = addFinding(findings, "assessment", id, "a review_required verdict must carry reasons")
		}
		if assessment.ProbeCount < 0 || assessment.SuccessCount < 0 || assessment.SuccessCount > assessment.ProbeCount {
			findings = addFinding(findings, "assessment", id, "probe_count and success_count are inconsistent")
		}
		if assessment.SuccessRatio < 0 || assessment.SuccessRatio > 1 {
			findings = addFinding(findings, "assessment", id, "success_ratio must be between 0 and 1")
		}
		if assessment.MaximumLatencyMS < 0 {
			findings = addFinding(findings, "assessment", id, "maximum_latency_ms must not be negative")
		}
		findings = appendDomainFindings(findings, "assessment", id, domain.ValidateRequestKey(assessment.RequestKey))
		if assessment.CreatedAt.IsZero() {
			findings = addFinding(findings, "assessment", id, "created_at is required")
		}
		if plan, ok := state.Plans[assessment.PlanID]; ok && plan.State == domain.PlanDraft {
			findings = addFinding(findings, "assessment", id, "a draft plan must not carry assessments")
		}
	}

	auditIDs := make(map[string]struct{}, len(state.AuditEvents))
	for index, event := range state.AuditEvents {
		label := fmt.Sprintf("audit_events[%d]", index)
		if !strings.HasPrefix(event.ID, "aud_") {
			findings = addFinding(findings, "audit_event", label, "audit event id must use the aud_ prefix")
		}
		if _, dup := auditIDs[event.ID]; dup {
			findings = addFinding(findings, "audit_event", label, "audit event id "+event.ID+" is duplicated")
		}
		auditIDs[event.ID] = struct{}{}
		if event.EntityType == "" || event.Action == "" {
			findings = addFinding(findings, "audit_event", label, "entity_type and action are required")
		}
		if event.At.IsZero() {
			findings = addFinding(findings, "audit_event", label, "at is required")
		}
	}

	return findings
}

func checkReferences(state domain.State) []Finding {
	findings := make([]Finding, 0)

	for _, id := range sortedKeys(state.Revisions) {
		revision := state.Revisions[id]
		if _, ok := state.Plans[revision.PlanID]; !ok {
			findings = addFinding(findings, "revision", id, "revision references missing plan "+revision.PlanID)
		}
	}

	for _, id := range sortedKeys(state.Plans) {
		plan := state.Plans[id]
		if plan.LatestRevisionID != "" {
			revision, ok := state.Revisions[plan.LatestRevisionID]
			if !ok {
				findings = addFinding(findings, "plan", id, "plan references missing revision "+plan.LatestRevisionID)
			} else if revision.PlanID != plan.ID {
				findings = addFinding(findings, "plan", id, "latest revision "+revision.ID+" belongs to plan "+revision.PlanID)
			}
		}
		if plan.LatestAssessmentID != "" {
			assessment, ok := state.Assessments[plan.LatestAssessmentID]
			if !ok {
				findings = addFinding(findings, "plan", id, "plan references missing assessment "+plan.LatestAssessmentID)
			} else if assessment.PlanID != plan.ID {
				findings = addFinding(findings, "plan", id, "latest assessment "+assessment.ID+" belongs to plan "+assessment.PlanID)
			}
		}
	}

	for _, id := range sortedKeys(state.LeaseGroups) {
		group := state.LeaseGroups[id]
		if _, ok := state.Plans[group.PlanID]; !ok {
			findings = addFinding(findings, "lease_group", id, "lease group references missing plan "+group.PlanID)
		}
		for _, leaseID := range group.LeaseIDs {
			lease, ok := state.Leases[leaseID]
			if !ok {
				findings = addFinding(findings, "lease_group", id, "lease group references missing lease "+leaseID)
				continue
			}
			if lease.AllocationID != group.ID {
				findings = addFinding(findings, "lease_group", id, "lease "+leaseID+" points to allocation "+lease.AllocationID)
			}
		}
	}

	for _, id := range sortedKeys(state.Leases) {
		lease := state.Leases[id]
		if _, ok := state.Plans[lease.PlanID]; !ok {
			findings = addFinding(findings, "lease", id, "lease references missing plan "+lease.PlanID)
		}
		node, nodeOK := state.Nodes[lease.NodeID]
		if !nodeOK {
			findings = addFinding(findings, "lease", id, "lease references missing node "+lease.NodeID)
		}
		group, groupOK := state.LeaseGroups[lease.AllocationID]
		if !groupOK {
			findings = addFinding(findings, "lease", id, "lease references missing lease group "+lease.AllocationID)
		} else {
			if group.PlanID != lease.PlanID {
				findings = addFinding(findings, "lease", id, "lease group "+group.ID+" belongs to plan "+group.PlanID)
			}
			if !containsString(group.LeaseIDs, lease.ID) {
				findings = addFinding(findings, "lease", id, "lease group "+group.ID+" does not list this lease")
			}
		}
		if lease.ProbeID != "" {
			probe, ok := state.Probes[lease.ProbeID]
			if !ok {
				findings = addFinding(findings, "lease", id, "lease references missing probe "+lease.ProbeID)
			} else if probe.LeaseID != lease.ID {
				findings = addFinding(findings, "lease", id, "probe "+probe.ID+" belongs to lease "+probe.LeaseID)
			}
		}
		if lease.State == domain.LeaseClaimed && nodeOK && node.State != domain.NodeLeased {
			findings = addFinding(findings, "lease", id, "claimed lease requires node "+lease.NodeID+" to be leased")
		}
	}

	for _, id := range sortedKeys(state.Probes) {
		probe := state.Probes[id]
		lease, leaseOK := state.Leases[probe.LeaseID]
		if !leaseOK {
			findings = addFinding(findings, "probe", id, "probe references missing lease "+probe.LeaseID)
		}
		if _, ok := state.Plans[probe.PlanID]; !ok {
			findings = addFinding(findings, "probe", id, "probe references missing plan "+probe.PlanID)
		}
		if _, ok := state.Nodes[probe.NodeID]; !ok {
			findings = addFinding(findings, "probe", id, "probe references missing node "+probe.NodeID)
		}
		if leaseOK {
			if lease.ProbeID != probe.ID {
				findings = addFinding(findings, "probe", id, "lease "+lease.ID+" does not reference this probe")
			}
			if lease.PlanID != probe.PlanID {
				findings = addFinding(findings, "probe", id, "probe plan does not match lease plan "+lease.PlanID)
			}
			if lease.NodeID != probe.NodeID {
				findings = addFinding(findings, "probe", id, "probe node does not match lease node "+lease.NodeID)
			}
		}
	}

	for _, id := range sortedKeys(state.Assessments) {
		assessment := state.Assessments[id]
		plan, planOK := state.Plans[assessment.PlanID]
		if !planOK {
			findings = addFinding(findings, "assessment", id, "assessment references missing plan "+assessment.PlanID)
		}
		revision, revisionOK := state.Revisions[assessment.RevisionID]
		if !revisionOK {
			findings = addFinding(findings, "assessment", id, "assessment references missing revision "+assessment.RevisionID)
		} else if revision.PlanID != assessment.PlanID {
			findings = addFinding(findings, "assessment", id, "assessed revision belongs to plan "+revision.PlanID)
		}
		if planOK && plan.LatestRevisionID != "" && plan.LatestRevisionID != assessment.RevisionID {
			findings = addFinding(findings, "assessment", id, "assessed revision is not the plan latest revision "+plan.LatestRevisionID)
		}
	}

	claimedByNode := make(map[string][]string)
	for _, id := range sortedKeys(state.Leases) {
		lease := state.Leases[id]
		if lease.State == domain.LeaseClaimed {
			claimedByNode[lease.NodeID] = append(claimedByNode[lease.NodeID], id)
		}
	}
	for _, id := range sortedKeys(state.Nodes) {
		node := state.Nodes[id]
		claimed := len(claimedByNode[node.ID])
		if node.State == domain.NodeLeased && claimed != 1 {
			findings = addFinding(findings, "node", id, fmt.Sprintf("leased node must hold exactly one claimed lease, found %d", claimed))
		}
		if node.State != domain.NodeLeased && claimed > 0 {
			findings = addFinding(findings, "node", id, "node is not leased but claimed leases exist")
		}
	}

	return findings
}

func checkIndexes(state domain.State) []Finding {
	findings := make([]Finding, 0)

	for _, key := range sortedKeys(state.LeaseRequestKeys) {
		groupID := state.LeaseRequestKeys[key]
		planID, requestKey, ok := splitIndexKey(key)
		if !ok {
			findings = addFinding(findings, "lease_request_keys", key, "index key must be plan id and request key")
			continue
		}
		if _, exists := state.Plans[planID]; !exists {
			findings = addFinding(findings, "lease_request_keys", key, "index references missing plan "+planID)
		}
		findings = appendDomainFindings(findings, "lease_request_keys", key, domain.ValidateRequestKey(requestKey))
		group, exists := state.LeaseGroups[groupID]
		if !exists {
			findings = addFinding(findings, "lease_request_keys", key, "index references missing lease group "+groupID)
			continue
		}
		if group.PlanID != planID || group.RequestKey != requestKey {
			findings = addFinding(findings, "lease_request_keys", key, "index entry does not match lease group "+groupID)
		}
	}
	for _, id := range sortedKeys(state.LeaseGroups) {
		group := state.LeaseGroups[id]
		key := group.PlanID + "\x00" + group.RequestKey
		indexed, exists := state.LeaseRequestKeys[key]
		if !exists {
			findings = addFinding(findings, "lease_group", id, "lease group is not present in the request key index")
		} else if indexed != group.ID {
			findings = addFinding(findings, "lease_group", id, "request key index points to lease group "+indexed)
		}
	}

	for _, key := range sortedKeys(state.AssessmentRequestKeys) {
		assessmentID := state.AssessmentRequestKeys[key]
		planID, requestKey, ok := splitIndexKey(key)
		if !ok {
			findings = addFinding(findings, "assessment_request_keys", key, "index key must be plan id and request key")
			continue
		}
		if _, exists := state.Plans[planID]; !exists {
			findings = addFinding(findings, "assessment_request_keys", key, "index references missing plan "+planID)
		}
		findings = appendDomainFindings(findings, "assessment_request_keys", key, domain.ValidateRequestKey(requestKey))
		assessment, exists := state.Assessments[assessmentID]
		if !exists {
			findings = addFinding(findings, "assessment_request_keys", key, "index references missing assessment "+assessmentID)
			continue
		}
		if assessment.PlanID != planID || assessment.RequestKey != requestKey {
			findings = addFinding(findings, "assessment_request_keys", key, "index entry does not match assessment "+assessmentID)
		}
	}
	for _, id := range sortedKeys(state.Assessments) {
		assessment := state.Assessments[id]
		key := assessment.PlanID + "\x00" + assessment.RequestKey
		indexed, exists := state.AssessmentRequestKeys[key]
		if !exists {
			findings = addFinding(findings, "assessment", id, "assessment is not present in the request key index")
		} else if indexed != assessment.ID {
			findings = addFinding(findings, "assessment", id, "request key index points to assessment "+indexed)
		}
	}

	return findings
}

func checkDigests(state domain.State) []Finding {
	findings := make([]Finding, 0)

	serialsByPlan := make(map[string]map[uint32]string)
	for _, id := range sortedKeys(state.Revisions) {
		revision := state.Revisions[id]
		if revision.EntryCount != len(revision.Entries) {
			findings = addFinding(findings, "revision", id, fmt.Sprintf(
				"entry_count %d does not match %d stored entries", revision.EntryCount, len(revision.Entries)))
		}
		normalized, err := domain.NormalizeRevisionInput(domain.RevisionCreateInput{
			Serial:    revision.Serial,
			Authority: revision.Authority,
			Entries:   revision.Entries,
		})
		if err == nil && !reflect.DeepEqual(normalized.Entries, revision.Entries) {
			findings = addFinding(findings, "revision", id, "entries are not stored in canonical order and form")
		}
		serials := serialsByPlan[revision.PlanID]
		if serials == nil {
			serials = make(map[uint32]string)
			serialsByPlan[revision.PlanID] = serials
		}
		if other, dup := serials[revision.Serial]; dup {
			findings = addFinding(findings, "revision", id, fmt.Sprintf(
				"serial %d is already used by revision %s in this plan", revision.Serial, other))
		}
		serials[revision.Serial] = revision.ID
	}

	for _, id := range sortedKeys(state.Plans) {
		plan := state.Plans[id]
		latestRevision := ""
		var latestSerial uint32
		for _, revision := range state.Revisions {
			if revision.PlanID != plan.ID {
				continue
			}
			if latestRevision == "" || revision.Serial > latestSerial {
				latestRevision = revision.ID
				latestSerial = revision.Serial
			}
		}
		if plan.LatestRevisionID != latestRevision {
			findings = addFinding(findings, "plan", id, fmt.Sprintf(
				"latest_revision_id %q does not match the newest stored revision %q", plan.LatestRevisionID, latestRevision))
		}
		// The service tags every newly created assessment as latest, so a
		// stored pointer is valid when it points to an assessment at the
		// newest timestamp; ids created within the same timestamp are tied,
		// not ordered.
		var latestAssessmentAt time.Time
		latestAtTime := make(map[string]struct{})
		for _, assessment := range state.Assessments {
			if assessment.PlanID != plan.ID {
				continue
			}
			switch {
			case assessment.CreatedAt.After(latestAssessmentAt):
				latestAssessmentAt = assessment.CreatedAt
				latestAtTime = map[string]struct{}{assessment.ID: {}}
			case assessment.CreatedAt.Equal(latestAssessmentAt):
				latestAtTime[assessment.ID] = struct{}{}
			}
		}
		if plan.LatestAssessmentID == "" {
			if len(latestAtTime) > 0 {
				findings = addFinding(findings, "plan", id, "plan has assessments but latest_assessment_id is empty")
			}
			continue
		}
		if _, ok := latestAtTime[plan.LatestAssessmentID]; !ok {
			findings = addFinding(findings, "plan", id, fmt.Sprintf(
				"latest_assessment_id %q does not point to an assessment at the newest timestamp %s",
				plan.LatestAssessmentID, latestAssessmentAt.Format(time.RFC3339Nano)))
		}
	}

	for _, id := range sortedKeys(state.Probes) {
		probe := state.Probes[id]
		expected := domain.ProbeFingerprint(probe.LeaseID, domain.ProbeInput{
			RequestKey:     probe.RequestKey,
			Success:        probe.Success,
			ObservedSerial: probe.ObservedSerial,
			LatencyMS:      probe.LatencyMS,
			ObservedAt:     probe.ObservedAt,
		})
		if expected != probe.PayloadFingerprint {
			findings = addFinding(findings, "probe", id, "payload_fingerprint does not match the stored probe content")
		}
	}

	for _, id := range sortedKeys(state.Assessments) {
		assessment := state.Assessments[id]
		plan, planOK := state.Plans[assessment.PlanID]
		revision, revisionOK := state.Revisions[assessment.RevisionID]
		if !planOK || !revisionOK {
			continue
		}
		probes := make([]domain.Probe, 0)
		for _, probe := range state.Probes {
			if probe.PlanID == assessment.PlanID {
				probes = append(probes, probe)
			}
		}
		recomputed := domain.BuildAssessment(assessment.ID, plan, revision, probes, assessment.CreatedAt)
		if recomputed.Verdict != assessment.Verdict {
			findings = addFinding(findings, "assessment", id, fmt.Sprintf(
				"verdict %q does not match the recomputed verdict %q", assessment.Verdict, recomputed.Verdict))
		}
		if !reflect.DeepEqual(recomputed.Reasons, assessment.Reasons) {
			findings = addFinding(findings, "assessment", id, "reasons do not match the recomputed reasons")
		}
		if recomputed.ProbeCount != assessment.ProbeCount ||
			recomputed.SuccessCount != assessment.SuccessCount ||
			recomputed.SuccessRatio != assessment.SuccessRatio ||
			recomputed.MaximumLatencyMS != assessment.MaximumLatencyMS {
			findings = addFinding(findings, "assessment", id, "stored counters do not match the recomputed assessment")
		}
	}

	return findings
}

func checkMapKey(findings []Finding, entity string, key string, id string, prefix string) []Finding {
	if id == "" {
		findings = addFinding(findings, entity, key, "id is required")
	} else {
		if key != id {
			findings = addFinding(findings, entity, key, fmt.Sprintf("map key %q does not match id %q", key, id))
		}
		if !strings.HasPrefix(id, prefix) {
			findings = addFinding(findings, entity, key, fmt.Sprintf("id %q must use the %s prefix", id, prefix))
		}
	}
	return findings
}

func appendDomainFindings(findings []Finding, entity string, id string, err error) []Finding {
	if err == nil {
		return findings
	}
	var domainErr *domain.DomainError
	if errors.As(err, &domainErr) && len(domainErr.Details) > 0 {
		keys := make([]string, 0, len(domainErr.Details))
		for key := range domainErr.Details {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			findings = addFinding(findings, entity, id, fmt.Sprintf("%s: %v", key, domainErr.Details[key]))
		}
		return findings
	}
	return addFinding(findings, entity, id, err.Error())
}

func addFinding(findings []Finding, entity string, id string, message string) []Finding {
	return append(findings, Finding{Entity: entity, ID: id, Message: message})
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func splitIndexKey(key string) (string, string, bool) {
	parts := strings.Split(key, "\x00")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'f' {
			continue
		}
		return false
	}
	return true
}

// duplicatedJSONKey tokenizes the raw document and reports the first dotted
// object path whose key appears more than once. A map-based decode cannot
// detect this because encoding/json keeps the last occurrence silently.
func duplicatedJSONKey(payload []byte) (string, bool) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	path, dup, err := scanJSONValue(decoder, "$")
	if err != nil {
		return "", false
	}
	return path, dup
}

// scanJSONValue consumes exactly one JSON value starting at the decoder's
// next token and recursively scans its contents.
func scanJSONValue(decoder *json.Decoder, prefix string) (string, bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", false, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return "", false, nil // scalar value
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return "", false, err
			}
			key, _ := keyToken.(string)
			path := prefix + "." + key
			if _, exists := seen[key]; exists {
				return path, true, nil
			}
			seen[key] = struct{}{}
			if nested, dup, err := scanJSONValue(decoder, path); err != nil {
				return "", false, err
			} else if dup {
				return nested, true, nil
			}
		}
		if _, err := decoder.Token(); err != nil { // closing brace
			return "", false, err
		}
	case '[':
		for index := 0; decoder.More(); index++ {
			entryPrefix := fmt.Sprintf("%s[%d]", prefix, index)
			if nested, dup, err := scanJSONValue(decoder, entryPrefix); err != nil {
				return "", false, err
			} else if dup {
				return nested, true, nil
			}
		}
		if _, err := decoder.Token(); err != nil { // closing bracket
			return "", false, err
		}
	}
	return "", false, nil
}
