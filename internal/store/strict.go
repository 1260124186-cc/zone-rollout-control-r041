package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"solo-0014-zone-rollout-control/internal/domain"
)

// StrictDecodeState decodes a snapshot payload with the strictest rules the
// offline recovery path requires: unknown fields, duplicate object keys and
// trailing data are all rejected instead of being silently ignored.
func StrictDecodeState(payload []byte) (domain.State, error) {
	if err := rejectDuplicateKeys(payload); err != nil {
		return domain.State{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var state domain.State
	if err := decoder.Decode(&state); err != nil {
		return domain.State{}, fmt.Errorf("decode snapshot: %w", err)
	}
	var extra json.Token
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return domain.State{}, fmt.Errorf("decode snapshot: trailing data after root object")
		}
		return domain.State{}, fmt.Errorf("decode snapshot: %w", err)
	}
	return Normalize(state), nil
}

func rejectDuplicateKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	return checkDuplicateKeys(decoder, "$")
}

func checkDuplicateKeys(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return fmt.Errorf("decode snapshot: %w", err)
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode snapshot: %w", err)
			}
			key := keyToken.(string)
			childPath := path + "." + key
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("decode snapshot: duplicate key %q", childPath)
			}
			seen[key] = struct{}{}
			if err := checkDuplicateKeys(decoder, childPath); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("decode snapshot: %w", err)
		}
	case '[':
		index := 0
		for decoder.More() {
			if err := checkDuplicateKeys(decoder, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
			index++
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("decode snapshot: %w", err)
		}
	}
	return nil
}
