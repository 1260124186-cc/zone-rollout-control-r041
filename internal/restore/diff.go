package restore

import (
	"bytes"
	"encoding/json"
	"sort"

	"solo-0014-zone-rollout-control/internal/domain"
)

// maxDiffIDs caps how many identifiers each diff bucket lists. Counts stay
// exact even when the identifier list is truncated.
const maxDiffIDs = 32

// diffStates compares the candidate against the current target state and
// summarizes, per collection, which objects a restore would add, replace,
// or remove.
func diffStates(candidate domain.State, current domain.State) *Diff {
	return &Diff{
		Plans:                 diffMaps(candidate.Plans, current.Plans),
		Revisions:             diffMaps(candidate.Revisions, current.Revisions),
		Nodes:                 diffMaps(candidate.Nodes, current.Nodes),
		Leases:                diffMaps(candidate.Leases, current.Leases),
		LeaseGroups:           diffMaps(candidate.LeaseGroups, current.LeaseGroups),
		Probes:                diffMaps(candidate.Probes, current.Probes),
		Assessments:           diffMaps(candidate.Assessments, current.Assessments),
		LeaseRequestKeys:      diffMaps(candidate.LeaseRequestKeys, current.LeaseRequestKeys),
		AssessmentRequestKeys: diffMaps(candidate.AssessmentRequestKeys, current.AssessmentRequestKeys),
		AuditEvents:           diffMaps(auditEventMap(candidate.AuditEvents), auditEventMap(current.AuditEvents)),
	}
}

func diffMaps[T any](candidate map[string]T, current map[string]T) EntityDiff {
	diff := EntityDiff{}
	for id, wanted := range candidate {
		existing, ok := current[id]
		if !ok {
			diff.Added++
			diff.AddedIDs = appendID(diff.AddedIDs, id, &diff.Truncated)
			continue
		}
		if entitiesEqual(wanted, existing) {
			diff.Unchanged++
			continue
		}
		diff.Replaced++
		diff.ReplacedIDs = appendID(diff.ReplacedIDs, id, &diff.Truncated)
	}
	for id := range current {
		if _, ok := candidate[id]; !ok {
			diff.Removed++
			diff.RemovedIDs = appendID(diff.RemovedIDs, id, &diff.Truncated)
		}
	}
	sort.Strings(diff.AddedIDs)
	sort.Strings(diff.ReplacedIDs)
	sort.Strings(diff.RemovedIDs)
	return diff
}

func appendID(ids []string, id string, truncated *bool) []string {
	if len(ids) >= maxDiffIDs {
		*truncated = true
		return ids
	}
	return append(ids, id)
}

func entitiesEqual[T any](left T, right T) bool {
	leftPayload, err := json.Marshal(left)
	if err != nil {
		return false
	}
	rightPayload, err := json.Marshal(right)
	if err != nil {
		return false
	}
	return bytes.Equal(leftPayload, rightPayload)
}

func auditEventMap(events []domain.AuditEvent) map[string]domain.AuditEvent {
	mapped := make(map[string]domain.AuditEvent, len(events))
	for _, event := range events {
		if _, exists := mapped[event.ID]; !exists {
			mapped[event.ID] = event
		}
	}
	return mapped
}
