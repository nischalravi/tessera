package api

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func (s *Server) attachScore(*store.Conn, *readiness.ConnectionView, time.Time) error { return nil }
