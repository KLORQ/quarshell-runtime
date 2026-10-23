// Package audit emits structured security / lifecycle events in OCSF shorthand
// (NVIDIA OpenShell–compatible) for agent observation via `cautem logs` / `cautem term`.
package audit

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"
)

// Event is a security-relevant sandbox decision.
type Event struct {
	Class    string // NET, HTTP, CONFIG, PROC, FINDING, LIFECYCLE, SSH
	Activity string // OPEN, GET, LOADED, …
	Severity string // INFO, LOW, MED, HIGH, CRIT, FATAL
	Action   string // ALLOWED, DENIED, FAILED, LOADED, …
	Details  string
	Context  string // optional bracket contents without []
}

// Emitter writes one audit event.
type Emitter interface {
	Emit(ev Event)
}

// WriterEmitter writes OCSF shorthand lines to W (default stderr).
type WriterEmitter struct {
	W io.Writer
}

// Emit writes one OCSF shorthand line.
func (e WriterEmitter) Emit(ev Event) {
	w := e.W
	if w == nil {
		w = os.Stderr
	}
	_, _ = fmt.Fprintln(w, Format(ev))
}

// SlogEmitter is a slog-backed emitter for MVP (works with slogx via slog.Default).
type SlogEmitter struct {
	Log *slog.Logger
}

// Emit logs the event at Info level with OCSF shorthand in the message.
func (e SlogEmitter) Emit(ev Event) {
	if e.Log == nil {
		e.Log = slog.Default()
	}
	e.Log.Info(Format(ev))
}

// Format renders `<ts> OCSF CLASS:ACTIVITY [SEVERITY] ACTION DETAILS [CONTEXT]`.
func Format(ev Event) string {
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	class := strings.TrimSpace(ev.Class)
	if class == "" {
		class = "NET"
	}
	activity := strings.TrimSpace(ev.Activity)
	if activity == "" {
		activity = "OTHER"
	}
	sev := strings.TrimSpace(ev.Severity)
	if sev == "" {
		sev = "INFO"
	}
	action := strings.TrimSpace(ev.Action)
	if action == "" {
		action = "OTHER"
	}
	details := strings.TrimSpace(ev.Details)
	if details == "" {
		details = "-"
	}
	msg := fmt.Sprintf("%s OCSF %s:%s [%s] %s %s", ts, class, activity, sev, action, details)
	if c := strings.TrimSpace(ev.Context); c != "" {
		if !strings.HasPrefix(c, "[") {
			c = "[" + c + "]"
		}
		msg += " " + c
	}
	return msg
}
