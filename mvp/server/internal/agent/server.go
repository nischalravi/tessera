package agent

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ServerTLSConfig is the TLS config of the agent listener: Tessera's own
// certificate (certFile, keyFile: the CA chain the agent pins signs it) and a
// required client certificate. The client certificate is not verified against
// a CA: the agent presents a self-signed one and Tessera pins its public key
// (PinOf), so a certificate issued by anyone else, however well signed, is
// not an agent. TLS 1.2 or later.
func ServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("agent listener certificate: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		// Possession of the key is proven by the handshake; the pin check in
		// the handler is the authorisation. VerifyPeerCertificate is not set
		// because there is no CA to verify against.
		ClientAuth: tls.RequireAnyClientCert,
	}, nil
}

// Handler serves the agent API (PathEnrol, PathHeartbeat, PathPoll, PathClaim, PathReport,
// PathResult). Mount it only on the mTLS listener: it reads the client key
// from the TLS connection state and refuses a request without one. pollWait
// is how long a poll is held (PollWait in production).
func (s *Service) Handler(pollWait time.Duration) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+PathEnrol, s.handleEnrol)
	mux.HandleFunc("POST "+PathHeartbeat, s.authed(s.handleHeartbeat))
	mux.HandleFunc("POST "+PathPoll, s.authed(func(w http.ResponseWriter, r *http.Request, p *Principal) {
		s.handlePoll(w, r, p, pollWait)
	}))
	mux.HandleFunc("POST "+PathResult, s.authed(s.handleResult))
	mux.HandleFunc("POST "+PathClaim, s.authed(func(w http.ResponseWriter, r *http.Request, p *Principal) {
		s.handleClaim(w, r, p, pollWait)
	}))
	mux.HandleFunc("POST "+PathReport, s.authed(s.handleReport))
	mux.HandleFunc("POST "+PathSealKey, s.authed(s.handleSealKey))
	return noStore(mux)
}

func noStore(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

// clientPin returns the pin of the TLS client certificate, or "" if none.
func clientPin(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return PinOf(r.TLS.PeerCertificates[0])
}

// decode reads one strict JSON object of at most max bytes.
func decode(w http.ResponseWriter, r *http.Request, max int64, v any) bool {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		writeErr(w, http.StatusBadRequest, "invalid_body")
		return false
	}
	return true
}

func (s *Service) handleEnrol(w http.ResponseWriter, r *http.Request) {
	pin := clientPin(r)
	if pin == "" {
		writeErr(w, http.StatusUnauthorized, "client_certificate_required")
		return
	}
	var req EnrolRequest
	if !decode(w, r, MaxRequestBytes, &req) {
		return
	}
	resp, err := s.Enrol(r.Context(), req, pin)
	switch {
	case errors.Is(err, ErrInvalidCode):
		writeErr(w, http.StatusForbidden, "invalid_code")
	case errors.Is(err, ErrProtocol):
		writeErr(w, http.StatusUpgradeRequired, "unsupported_protocol")
	case err != nil && isInput(err):
		writeErr(w, http.StatusBadRequest, "invalid_body")
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "internal")
	default:
		writeJSON(w, http.StatusOK, resp)
	}
}

func isInput(err error) bool { return errors.Is(err, ErrBadInput) }

// authed authenticates the client key and passes the principal on.
func (s *Service) authed(fn func(http.ResponseWriter, *http.Request, *Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pin := clientPin(r)
		if pin == "" {
			writeErr(w, http.StatusUnauthorized, "client_certificate_required")
			return
		}
		p, err := s.Authenticate(r.Context(), pin)
		if errors.Is(err, ErrUnauthorized) {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal")
			return
		}
		fn(w, r, p)
	}
}

func (s *Service) handleHeartbeat(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req HeartbeatRequest
	if !decode(w, r, MaxRequestBytes, &req) {
		return
	}
	switch err := s.Heartbeat(r.Context(), p, req); {
	case errors.Is(err, ErrProtocol):
		writeErr(w, http.StatusUpgradeRequired, "unsupported_protocol")
	case errors.Is(err, ErrUnauthorized):
		writeErr(w, http.StatusUnauthorized, "unauthorized")
	case err != nil && isInput(err):
		writeErr(w, http.StatusBadRequest, "invalid_body")
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "internal")
	default:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "min_version": MinVersion})
	}
}

func (s *Service) handlePoll(w http.ResponseWriter, r *http.Request, p *Principal, wait time.Duration) {
	var empty struct{}
	if r.ContentLength != 0 && !decode(w, r, 1<<10, &empty) {
		return
	}
	j, err := s.Hub.Poll(r.Context(), p.Tenant, p.AgentID, wait)
	switch {
	case errors.Is(err, ErrRevoked):
		writeErr(w, http.StatusUnauthorized, "unauthorized")
	case err != nil:
		// the agent went away mid-poll
		w.WriteHeader(http.StatusNoContent)
	case j == nil:
		w.WriteHeader(http.StatusNoContent)
	default:
		writeJSON(w, http.StatusOK, j)
	}
}

func (s *Service) handleResult(w http.ResponseWriter, r *http.Request, p *Principal) {
	var res Result
	if !decode(w, r, MaxResultBytes, &res) {
		return
	}
	if res.JobID == "" || (res.Error == nil && !json.Valid(res.Payload)) {
		writeErr(w, http.StatusBadRequest, "invalid_body")
		return
	}
	if res.Error != nil && (len(res.Error.Code) > 64 || len(res.Error.Message) > 512 || res.Error.Code == "revoked") {
		writeErr(w, http.StatusBadRequest, "invalid_body")
		return
	}
	if err := s.Hub.Complete(p.Tenant, p.AgentID, res); err != nil {
		writeErr(w, http.StatusNotFound, "unknown_job")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Service) handleClaim(w http.ResponseWriter, r *http.Request, p *Principal, wait time.Duration) {
	var empty struct{}
	if r.ContentLength != 0 && !decode(w, r, 1<<10, &empty) {
		return
	}
	j, err := s.Claim(r.Context(), p, wait)
	switch {
	case errors.Is(err, ErrUnauthorized):
		writeErr(w, http.StatusUnauthorized, "unauthorized")
	case err != nil && r.Context().Err() != nil:
		// the agent went away mid-poll
		w.WriteHeader(http.StatusNoContent)
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "internal")
	case j == nil:
		w.WriteHeader(http.StatusNoContent)
	default:
		writeJSON(w, http.StatusOK, j)
	}
}

func (s *Service) handleReport(w http.ResponseWriter, r *http.Request, p *Principal) {
	var res PullResult
	if !decode(w, r, MaxSyncResultBytes, &res) {
		return
	}
	if res.JobID == "" || len(res.JobID) > 64 ||
		(res.Error != nil && (len(res.Error.Code) > 64 || len(res.Error.Message) > 512 || res.Error.Code == "revoked")) {
		writeErr(w, http.StatusBadRequest, "invalid_body")
		return
	}
	switch err := s.Report(r.Context(), p, res); {
	case errors.Is(err, ErrUnknownJob):
		writeErr(w, http.StatusNotFound, "unknown_job")
	case errors.Is(err, ErrUnauthorized):
		writeErr(w, http.StatusUnauthorized, "unauthorized")
	case errors.Is(err, ErrBadInput):
		writeErr(w, http.StatusBadRequest, "invalid_body")
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "internal")
	default:
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func (s *Service) handleSealKey(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req SealKeyRequest
	if !decode(w, r, MaxRequestBytes, &req) {
		return
	}
	switch id, err := s.RegisterSealKey(r.Context(), p, req); {
	case errors.Is(err, ErrProtocol):
		writeErr(w, http.StatusUpgradeRequired, "unsupported_protocol")
	case errors.Is(err, ErrUnauthorized):
		writeErr(w, http.StatusUnauthorized, "unauthorized")
	case errors.Is(err, ErrBadInput):
		writeErr(w, http.StatusBadRequest, "invalid_body")
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "internal")
	default:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "key_id": id})
	}
}
