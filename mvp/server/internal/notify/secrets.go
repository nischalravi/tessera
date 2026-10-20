package notify

import (
	"sync"
	"time"
)

// Secrets hands a one-time secret (a claim link, a confirmation code) from the
// request that created it to the dispatcher that mails it, without the secret
// ever being written to the database: the notification row says only that a
// guest invitation or code is to be sent, the email's one secret line is
// supplied here at send time. Entries are kept in memory until the
// notification is final (sent, dead or skipped) or they expire.
//
// A restart loses them: the dispatcher then makes the notification a dead
// letter with a clear error, and the sponsor or the guest asks for a new link.
// That is the price of storing claim secrets only as hashes.
type Secrets struct {
	mu sync.Mutex
	m  map[string]secretEntry
}

type secretEntry struct {
	text  string
	until time.Time
}

// maxSecrets bounds the table; a full table drops expired entries first and
// then refuses new ones (the caller's notification becomes a dead letter).
const maxSecrets = 20000

// NewSecrets returns an empty handoff.
func NewSecrets() *Secrets { return &Secrets{m: map[string]secretEntry{}} }

// Put keeps text for the notification until it is dropped or until.
func (s *Secrets) Put(notificationID, text string, until time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) >= maxSecrets {
		now := time.Now()
		for k, e := range s.m {
			if !now.Before(e.until) {
				delete(s.m, k)
			}
		}
		if len(s.m) >= maxSecrets {
			return
		}
	}
	s.m[notificationID] = secretEntry{text, until}
}

// Get returns the secret of a notification, if it is still held.
func (s *Secrets) Get(notificationID string, now time.Time) (string, bool) {
	if s == nil {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[notificationID]
	if !ok || !now.Before(e.until) {
		delete(s.m, notificationID)
		return "", false
	}
	return e.text, true
}

// Drop forgets the secret of a notification.
func (s *Secrets) Drop(notificationID string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.m, notificationID)
	s.mu.Unlock()
}

// Len is how many secrets are held (tests).
func (s *Secrets) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// SecretKind reports whether a notification kind carries a one-time secret
// supplied at send time (see Secrets).
func SecretKind(kind string) bool {
	return kind == KindGuestInvitation || kind == KindClaimCode || kind == KindGuestRenewalLink || kind == KindGuestRecoveryLink
}
