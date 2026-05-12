package core

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// NDJSONEmitter serializes Records as newline-delimited JSON to an
// io.Writer. It is goroutine-safe: Emit may be called from multiple
// goroutines and the resulting NDJSON stream remains well-formed
// (one record per line, no interleaving).
type NDJSONEmitter struct {
	mu  sync.Mutex
	bw  *bufio.Writer
	enc *json.Encoder
}

// NewNDJSONEmitter wraps w with a buffered writer and a json.Encoder
// configured for compact, deterministic output:
//   - HTML escaping disabled (we never embed records in HTML);
//   - no SetIndent: one record per line, no pretty-print.
//
// Callers MUST invoke Close to flush the buffer before exit.
func NewNDJSONEmitter(w io.Writer) *NDJSONEmitter {
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	return &NDJSONEmitter{bw: bw, enc: enc}
}

// Emit serializes rec as a single NDJSON line. It is safe for
// concurrent use.
func (e *NDJSONEmitter) Emit(rec Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.enc.Encode(rec); err != nil {
		return fmt.Errorf("emit record (module=%s site_class=%s): %w",
			rec.Module, rec.SiteClass, err)
	}
	return nil
}

// Close flushes the underlying buffered writer. It does NOT close the
// underlying io.Writer; callers retain ownership of that.
func (e *NDJSONEmitter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.bw.Flush()
}
