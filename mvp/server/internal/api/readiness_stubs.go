package api

import (
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func (s *Server) attachScore(*store.Conn, *readiness.ConnectionView, time.Time) error { return nil }

func (s *Server) firstSync(*http.Request, *store.Conn, readiness.ActiveConnection, time.Time) error {
	return nil
}
