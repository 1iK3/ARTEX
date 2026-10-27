package db

import "encoding/json"

// cloneRawJSON returns a private copy of a JSONB scan buffer. pgx may reuse
// row buffers, and JSON payloads are never shared between callers or cached.
func cloneRawJSON(raw []byte) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	out := make(json.RawMessage, len(raw))
	copy(out, raw)
	return out
}
