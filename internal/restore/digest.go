package restore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"solo-0014-zone-rollout-control/internal/domain"
)

// digestOf returns a stable content digest of a normalized state. Go renders
// maps with sorted keys, so the same state always produces the same digest.
// Two snapshots with equal digests are interchangeable for restore purposes.
func digestOf(state domain.State) (string, error) {
	payload, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
