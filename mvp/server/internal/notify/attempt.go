package notify

import (
	"context"
	"crypto/tls"
	"regexp"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Outcomes of one send attempt; they are the delivery log's statuses.
const (
	OutcomeAccepted = store.EmailAccepted // 250 at the end of DATA: accepted by the relay, not delivered to the inbox
	OutcomeDeferred = store.EmailDeferred // 4xx
	OutcomeRejected = store.EmailRejected // 5xx, or a recipient that can never work
	OutcomeFailed   = store.EmailFailed   // network or TLS error, timeout
)

// Transcript limits: a message's log is bounded however chatty the relay is.
const (
	MaxSteps      = 120
	MaxFieldLen   = 300
	MaxTranscript = 24 << 10
)

// Step is one command and the relay's reply.
type Step struct {
	Command  string `json:"command"`
	Reply    string `json:"reply"`
	Code     int    `json:"code"`
	Enhanced string `json:"enhanced,omitempty"` // the enhanced status code, e.g. 2.0.0
}

// TLSInfo is the result of the STARTTLS upgrade (or implicit TLS).
type TLSInfo struct {
	Version string `json:"version,omitempty"`
	Cipher  string `json:"cipher,omitempty"`
	Subject string `json:"server_subject,omitempty"` // the server certificate
	Issuer  string `json:"server_issuer,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Attempt is the record of one send attempt: what the relay said, never the
// message body and never a credential (AUTH is recorded as <redacted>).
type Attempt struct {
	Started      time.Time `json:"started_at"`
	Finished     time.Time `json:"finished_at"`
	Outcome      string    `json:"outcome"`
	Banner       string    `json:"banner,omitempty"`
	Capabilities []string  `json:"capabilities,omitempty"`
	TLS          *TLSInfo  `json:"tls,omitempty"`
	Steps        []Step    `json:"steps"`
	MailFrom     string    `json:"mail_from,omitempty"`
	RcptTo       string    `json:"rcpt_to,omitempty"`
	QueueID      string    `json:"queue_id,omitempty"`
	Error        string    `json:"error,omitempty"`
	Truncated    bool      `json:"truncated,omitempty"`

	size int
}

// RecordingSender is a Sender that also returns the transcript of the attempt.
type RecordingSender interface {
	Sender
	SendRecorded(ctx context.Context, e Email) (*Attempt, error)
}

var enhancedRE = regexp.MustCompile(`^([245])\.(\d{1,3})\.(\d{1,3})\b`)

func clipField(s string) string {
	if len(s) <= MaxFieldLen {
		return s
	}
	return s[:MaxFieldLen] + "…"
}

// step appends a command and reply, keeping the transcript within its caps.
func (a *Attempt) step(command string, code int, reply string) {
	if len(a.Steps) >= MaxSteps || a.size >= MaxTranscript {
		a.Truncated = true
		return
	}
	s := Step{Command: clipField(command), Reply: clipField(reply), Code: code}
	if m := enhancedRE.FindString(reply); m != "" {
		s.Enhanced = m
	}
	a.size += len(s.Command) + len(s.Reply) + 16
	a.Steps = append(a.Steps, s)
}

var queueIDRE = []*regexp.Regexp{
	regexp.MustCompile(`(?i)queued as ([A-Za-z0-9._-]+)`),
	regexp.MustCompile(`(?i)\bid[= ]([A-Za-z0-9._-]+)`),
	regexp.MustCompile(`(?i)\bqueue id[: ]+([A-Za-z0-9._-]+)`),
}

// ParseQueueID extracts the relay's queue id from the final 250 reply, for
// example "250 2.0.0 Ok: queued as ABC123" or "250 OK id=1abc-000".
func ParseQueueID(reply string) string {
	for _, re := range queueIDRE {
		if m := re.FindStringSubmatch(reply); m != nil {
			return strings.TrimRight(m[1], ".")
		}
	}
	return ""
}

func tlsInfo(cs tls.ConnectionState) *TLSInfo {
	t := &TLSInfo{Version: tls.VersionName(cs.Version), Cipher: tls.CipherSuiteName(cs.CipherSuite)}
	if len(cs.PeerCertificates) > 0 {
		t.Subject, t.Issuer = cs.PeerCertificates[0].Subject.String(), cs.PeerCertificates[0].Issuer.String()
	}
	return t
}

// RecordStep appends a command and reply to a transcript, within its caps
// (exported for the tests of the caps).
func RecordStep(a *Attempt, command string, code int, reply string) { a.step(command, code, reply) }
